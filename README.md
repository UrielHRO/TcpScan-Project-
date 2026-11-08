# tcpscan

A TCP port scanner in Python with banner grabbing and JSON/Markdown reporting. It is a study project, written to understand what happens under the hood in the first phase of reconnaissance with tools like nmap. It comes with a local test lab (`lab_server.py`) that checks the scanner against a known set of services.

> **Authorized use only.** Scan only targets you own or have explicit permission to test (your own lab, Hack The Box, TryHackMe, `scanme.nmap.org`). Scanning systems you do not have permission to test may be illegal.

## Features

- TCP connect scan (full handshake) using a thread pool.
- Classifies each port as `open`, `closed` or `filtered`.
- Banner grabbing: reads the banner a service announces on its own (SSH, FTP, SMTP) and, if nothing arrives, sends a minimal HTTP `HEAD /` request.
- Port selection by list (`22,80,443`), range (`1-1024`), the `top` shortcut (27 common ports) or `all` (1-65535).
- Results as JSON for scripting and as a Markdown report for reading.
- Standard library only. No external dependencies.

## Requirements

- Python 3.9 or newer.

## Project layout

| File | Purpose |
|---|---|
| `tcpscan.py` | The scanner |
| `lab_server.py` | Local test lab and automated check for the scanner |
| `README.md` | This file |

## Installation

```bash
git clone https://github.com/<your-username>/tcpscan.git
cd tcpscan
python tcpscan.py --help
```

## Usage

```bash
# Ports 1-1024 (default)
python tcpscan.py 127.0.0.1

# Specific ports
python tcpscan.py 10.10.10.5 -p 22,80,443,8080

# Common ports shortcut, saving JSON and a report
python tcpscan.py scanme.nmap.org -p top --json out.json --md report.md

# All ports, more threads, no banner grabbing
python tcpscan.py 192.168.56.101 -p all -t 300 --no-banner -q
```

### Options

| Option | Description | Default |
|---|---|---|
| `host` | Target hostname or IPv4 address | required |
| `-p`, `--ports` | `22,80`, `1-1024`, `top` or `all` | `1-1024` |
| `-t`, `--threads` | Concurrent connections | `100` |
| `--timeout` | Connection timeout in seconds | `1.0` |
| `--banner-timeout` | Banner wait time in seconds | `1.5` |
| `--no-banner` | Disable banner grabbing | off |
| `--json FILE` | Save results as JSON | not saved |
| `--md FILE` | Save a Markdown report | not saved |
| `--all-states` | Include `closed` and `filtered` ports in the JSON | open only |
| `-q`, `--quiet` | Do not print open ports while scanning | off |

Exit codes: `0` on success, `2` for invalid arguments, `1` if the host cannot be resolved, `130` if interrupted with Ctrl+C.

## Example output

Scan of the local test lab on Windows (see [Testing](#testing)):

```text
PS> python tcpscan.py 127.0.0.1 -p 9020-9030,9080,9090 --timeout 3
Warning: only scan targets you own or are authorized to test.
Scanning 127.0.0.1 (13 ports)...
[+] 9021/tcp open (unknown)  220 lab-ftpd ready
[+] 9022/tcp open (unknown)  SSH-2.0-OpenSSH_8.9p1 lab
[+] 9025/tcp open (unknown)  220 mail.lab ESMTP ready
[+] 9080/tcp open (unknown)  HTTP/1.1 200 OK
[+] 9090/tcp open (unknown)

Done in 2.04 s: 5 open, 8 closed, 0 filtered.
```

Excerpt of the JSON written with `--json`:

```json
{
  "target": "127.0.0.1",
  "ip": "127.0.0.1",
  "summary": { "open": 5, "closed": 8, "filtered": 0 },
  "results": [
    { "port": 9021, "state": "open", "service": "unknown", "banner": "220 lab-ftpd ready" },
    { "port": 9022, "state": "open", "service": "unknown", "banner": "SSH-2.0-OpenSSH_8.9p1 lab" }
  ]
}
```

The report written with `--md` has the target, start time (UTC), duration, scan parameters and a table of open ports:

```markdown
# TCP scan report: 127.0.0.1

- Target: `127.0.0.1` (127.0.0.1)
- Ports scanned: 13 (threads: 100, timeout: 3.0 s)
- Summary: 5 open, 8 closed, 0 filtered

## Open ports

| Port | Service | Banner |
|---|---|---|
| 9021/tcp | unknown | 220 lab-ftpd ready |
| 9022/tcp | unknown | SSH-2.0-OpenSSH_8.9p1 lab |
| 9025/tcp | unknown | 220 mail.lab ESMTP ready |
| 9080/tcp | unknown | HTTP/1.1 200 OK |
| 9090/tcp | unknown |  |
```

## Testing

`lab_server.py` starts five fake services on `127.0.0.1` (it never binds to any other address) and knows exactly what the scanner should find:

| Port | Behavior |
|---|---|
| 9021 | Announces an FTP banner |
| 9022 | Announces an SSH banner |
| 9025 | Announces an SMTP banner |
| 9080 | Answers an HTTP request with `200 OK` |
| 9090 | Accepts the connection and never replies |

The other scanned ports (9020, 9023, 9024, 9026 to 9030) have nothing listening and must come back as `closed`.

### Automated check

```bash
python lab_server.py --verify
```

It starts the lab, runs the scanner against it twice (with and without banner grabbing), compares the results with the expected ones and exits with code `0` only if everything matches. Output on Windows:

```text
[PASS] scanner exits with code 0  (exit 0)
[PASS] open ports match the lab exactly  (expected [9021, 9022, 9025, 9080, 9090], got [9021, 9022, 9025, 9080, 9090])
[PASS] all other scanned ports reported as closed  (8 of 8)
[PASS] banner on 9021 (fake FTP)  (got '220 lab-ftpd ready')
[PASS] banner on 9022 (fake SSH)  (got 'SSH-2.0-OpenSSH_8.9p1 lab')
[PASS] banner on 9025 (fake SMTP)  (got '220 mail.lab ESMTP ready')
[PASS] banner on 9080 (fake HTTP)  (got 'HTTP/1.1 200 OK')
[PASS] banner on 9090 (silent)  (got '')
[PASS] summary counts are consistent  ({'open': 5, 'closed': 8, 'filtered': 0})
[PASS] --no-banner returns no banners

10/10 checks passed
```

`lab_server.py` looks for `tcpscan.py` in its own folder. Use `--scanner PATH` if they are in different places.

### Manual check

Run the lab in one terminal and the scanner in another. The lab prints a line for each connection it receives, so you can watch the scan arrive:

```bash
# terminal 1
python lab_server.py

# terminal 2
python tcpscan.py 127.0.0.1 -p 9020-9030,9080,9090 --timeout 3
```

Do not run `--verify` while the lab is already running, because both need the same ports.

### Windows timeout behavior

On Windows, a refused connection takes about 2 seconds to be reported, even on localhost. With the default 1 s timeout, the scanner gives up first and reports closed ports as `filtered`. The same lab scanned twice on Windows:

| Command | Result |
|---|---|
| `python tcpscan.py 127.0.0.1 -p 9020-9030,9080,9090` | 5 open, 0 closed, 8 filtered (1.03 s) |
| `python tcpscan.py 127.0.0.1 -p 9020-9030,9080,9090 --timeout 3` | 5 open, 8 closed, 0 filtered (2.04 s) |

Use `--timeout 3` on Windows when you need to tell closed from filtered. Linux reports the refusal immediately, so the default works there. This is why `--verify` runs the scanner with a 3 s timeout.

### Other targets

Suggested targets for real use: your own virtual machines (DVWA, Metasploitable, Juice Shop), TryHackMe rooms, Hack The Box machines and `scanme.nmap.org`. The Nmap project authorizes scanning that host for testing, with a limit of about a dozen scans per day, and the permission does not cover exploit or denial-of-service testing (see [Legal Issues](https://nmap.org/book/legal-issues.html)).

## How it works

For each port, a worker thread opens a TCP socket and calls `connect()` with a timeout:

| `connect()` result | Classification | Meaning |
|---|---|---|
| Connection established | `open` | A service is listening |
| `ConnectionRefusedError` | `closed` | The host answered with RST, nothing is listening |
| Timeout or network error | `filtered` | No answer, usually a firewall or a host that is down |

On open ports, the scanner reads whatever the service sends. If nothing arrives, it sends a minimal HTTP request and reads the reply. Only the first line (up to 200 characters) is kept.

## Limitations

- IPv4 only.
- Connect scan only. No SYN scan, which would need raw sockets and root privileges.
- The service name comes from the port number (`getservbyport`) and not from fingerprinting. An HTTP server on port 9080 shows up as `unknown`. Verify manually.
- Banners on TLS ports (443, 993, 995) are usually empty, because the plain-text probe does not complete a TLS handshake.
- A connect scan is easy to spot in target logs and may trigger an IDS. There is no stealth technique of any kind.
- With a low timeout on slow networks, open ports can show up as `filtered`. Adjust `--timeout` and `-t` and scan again. See also [Windows timeout behavior](#windows-timeout-behavior).
- A scan of all 65535 ports against a host that drops packets is slow: with the default 100 threads and 1 s timeout it takes roughly 11 minutes.

## Comparison with nmap

nmap is much faster, more accurate and far more complete (SYN scan, version detection, scripting engine, IPv6, OS detection). This project does not try to replace it. It exists to show, in a few dozen lines, what happens during a TCP scan and how to structure usable report output.

## References

- [Nmap Network Scanning, TCP Connect Scan (-sT)](https://nmap.org/book/scan-methods-connect-scan.html): what a connect scan is and when Nmap falls back to it.
- [Nmap Network Scanning, TCP SYN (Stealth) Scan (-sS)](https://nmap.org/book/synscan.html): the half-open scan this project does not implement.
- [Nmap Network Scanning, Legal Issues](https://nmap.org/book/legal-issues.html): authorization for port scanning and the rules for `scanme.nmap.org`.
- [Scanme.Nmap.Org](http://scanme.nmap.org/): the host the Nmap project provides for scan testing.
- [Python docs, concurrent.futures](https://docs.python.org/3/library/concurrent.futures.html): `ThreadPoolExecutor` and `as_completed`, used for the worker pool.
- [Python standard library index](https://docs.python.org/3/library/index.html): `socket` and `socketserver`, used by the scanner and the test lab.

### Further reading

- [Python 3 Programming Tutorial: Sockets simple port scanner](https://www.youtube.com/watch?v=szm3camsf8k) (sentdex): a basic sequential scanner built on sockets.
- [Python 3 Programming Tutorial: Threaded port scanner](https://www.youtube.com/watch?v=icE6PR19C0Y) (sentdex): the threaded version of the same scanner.
- [How to Make a Port Scanner in Python](https://www.thepythoncode.com/article/make-port-scanner-python) (The Python Code): an article that goes from a simple scanner to a threaded one.
