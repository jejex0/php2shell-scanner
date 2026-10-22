php2shell-scanner
=================

Standalone scanner and authorized RCE verification for CVE-2026-109618 /
CVE-2026-109619 (PHP session.upload_progress heap corruption).


WARNING
-------
Only use this tool on systems you own or have explicit written authorization
to test. Active probing and exploitation are intrusive: requests exhaust PHP
memory, can abort Apache prefork workers, and may disrupt production traffic.
Confirm scope before running it.


WHAT IT DOES
------------
- Scans a single URL, a file of hosts/URLs, or subdomains enumerated via crt.sh.
- Fingerprints PHP from X-Powered-By and response bodies.
- For hosts without an advertised version, sends a minimal multipart control
  request and up to three crafted probes (1/8/20 MiB, capped by
  --max-probe-mb).
- Distinguishes CVE-specific crashes from generic low-memory crashes by
  replaying a same-size benign multipart body.
- Reports HIGH confidence for an unpatched advertised version, an oversized
  PHPSESSID Set-Cookie, or "Session object destruction failed".
- Automatically exploits HIGH-confidence Apache mod_php targets: heap leak,
  libphp leak, forged pDestructor -> system, executes id>./<proof>, fetches
  the proof over HTTP, prints the id output, and removes the proof unless
  --no-cleanup is used.
- Prints only vulnerable host URLs and command output to stdout; progress and
  diagnostics go to stderr.


REQUIREMENTS
------------
- Python 3.9 or newer. The tool uses only the Python standard library.
- A Linux host for running the scanner.
- Exploit target: Linux Apache prefork + mod_php with display_errors=1,
  memory_limit around 8M, max_input_vars=1000, session.use_cookies=1,
  session.use_strict_mode=0, session.upload_progress.enabled=1,
  expose_php=On, and a web root writable by the PHP user.
- The embedded stage calibration is for php:8.4.26-apache. Other builds need
  matching --zif-offset, --dtor-offset, and --htdata-offset values and may
  need recalibration.


INSTALL
-------
  git clone <this-repo>
  cd php2shell-scanner
  python3 -m venv .venv
  . .venv/bin/activate
  pip install -r requirements.txt

No third-party packages are required.


USAGE
-----
  python3 php2shell.py -f subdomains.txt
  python3 php2shell.py -f subdomains.txt --fast --workers 24 --rate 25
  python3 php2shell.py -f subdomains.txt --safe --no-exploit
  python3 php2shell.py -u https://target/ --shell
  python3 php2shell.py -u https://target/ --container php2shell-target -v

Common options:
  -f, --file        file of hosts/URLs, one per line
  -u, --url         single target
  --domain          enumerate subdomains via crt.sh
  --safe            version fingerprint only (one GET; no OOM probes)
  --no-exploit      scan only; never run the exploit
  --exploit-likely  also exploit LIKELY hosts (default: HIGH only)
  --fast            send only the 1 MiB probe
  --max-probe-mb    largest probe to send, 1-20 MiB (default: 8)
  --workers         scan threads (default: 16)
  --rate            global request starts per second (default: 25; 0 = unlimited)
  --shell           command console on a single verified target
  -k, --insecure    skip TLS certificate verification
  -v, --verbose     print per-host reasons to stderr

Examples:
  # Least intrusive: one GET per host, version fingerprint only.
  python3 php2shell.py -f subdomains.txt --safe --no-exploit -v

  # Active scan with 1 MiB probes, no exploitation.
  python3 php2shell.py -f subdomains.txt --fast --no-exploit --workers 8 --rate 10

  # Full scan and automatic exploitation of HIGH-confidence hosts.
  python3 php2shell.py -f subdomains.txt --workers 16 --rate 20

  # Derive zif_system/zval_ptr_dtor offsets from a local lab container.
  python3 php2shell.py -f subdomains.txt --container php2shell-target


VERDICTS
--------
  VULNERABLE    HIGH confidence: unpatched advertised version, oversized
                PHPSESSID Set-Cookie, or destruction-failure signal.
  LIKELY        Multipart-specific crash without a strong signal. Not
                auto-exploited unless --exploit-likely is given.
  FIXED         Advertised PHP version is patched.
  BLOCKED       Request rejected (400/403/413/429), often by a CDN or WAF.
  INCONCLUSIVE  Timeout, 5xx, reset, rejected probe, or no differential result.
  NO SIGNAL     Probes completed; no crash and no PHP version advertised.
  ERROR         Initial GET failed (DNS, TLS, connection, timeout, bad URL).


EXIT CODES
----------
  0    No high-confidence host found (or no exploit was attempted).
  1    High-confidence host(s) found or exploitation/shell attempted.
  130  Interrupted (Ctrl-C).


LIMITATIONS
-----------
- The exploit chain is calibrated for PHP 8.4.26 / mod_php prefork. PHP 8.5.x
  is detected but not exploited by this chain. Hosts that hide X-Powered-By
  (expose_php=Off) are usually only LIKELY and generally fail stage 3.
- nginx/FPM and IIS targets are detected but cannot be exploited by this
  chain.
- The injected command is limited to 14 bytes. Output is redirected to
  ./<proof> in the web root, so the PHP user must be able to write there.
- The exploit is disruptive: it exhausts memory and aborts workers. Use
  --safe when you only need a fingerprint of production hosts.


AUTHORIZATION
-------------
This project is provided for authorized security testing and vulnerability
research. You are responsible for confirming that every target is in scope
and that you have permission to perform intrusive testing.
