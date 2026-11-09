# tcpscan

A TCP port scanner in Python with banner grabbing, service identification and JSON/Markdown reporting. It is a study project, written to understand what happens under the hood in the first phase of reconnaissance with tools like nmap. It comes with a local test lab (`lab_server.py`) that checks the scanner against a known set of services.

> **Authorized use only.** Scan only targets you own or have explicit permission to test (your own lab, TryHackMe, scanme.nmap.org). Scanning systems you do not have permission to test may be illegal.

## Features

- TCP connect scan (full handshake) using a thread pool.
- Classifies each port as `open`, `closed` or `filtered`.
- Banner grabbing. It reads the banner a service announces on its own (SSH, FTP, SMTP) and, if nothing arrives, sends a minimal `HTTP HEAD /` request.
- Service identification from the banner (ssh, http, ftp, smtp, imap, vnc). Without a usable banner it falls back to the port number.
- Port selection by list (`22,80,443`), range (`1-1024`), the `top` shortcut (27 common ports) or `all` (1-65535).
- Results as JSON for scripting and as a Markdown report for reading.
- Standard library only. No external dependencies.

## Example output

Scan of the local test lab (see [Testing](#testing)), run on Linux:

```
$ python tcpscan.py 127.0.0.1 -p 9020-9030,9080,9090 --timeout 3
Warning: only scan targets you own or are authorized to test.
Scanning 127.0.0.1 (13 ports)...
[+] 9022/tcp open (ssh)  SSH-2.0-OpenSSH_8.9p1 lab
[+] 9021/tcp open (ftp)  220 lab-ftpd ready
[+] 9025/tcp open (smtp)  220 mail.lab ESMTP ready
[+] 9080/tcp open (http)  HTTP/1.1 200 OK
[+] 9090/tcp open (unknown)

Done in 0.75 s: 5 open, 8 closed, 0 filtered.
```

Ports are printed as the scan finishes them, so the order can vary. The saved reports are sorted by port.

Excerpt of the JSON written with `--json`. `service_source` says where the service name came from (`banner`, `port`, or empty when unknown):

```json
{
  "target": "127.0.0.1",
  "ip": "127.0.0.1",
  "summary": { "open": 5, "closed": 8, "filtered": 0 },
  "results": [
    { "port": 9021, "state": "open", "service": "ftp", "service_source": "banner", "banner": "220 lab-ftpd ready" },
    { "port": 9022, "state": "open", "service": "ssh", "service_source": "banner", "banner": "SSH-2.0-OpenSSH_8.9p1 lab" }
  ]
}
```

The full files from this scan are in [`examples/`](examples/): [`lab_report.md`](examples/lab_report.md) (the `--md` report) and [`lab_scan.json`](examples/lab_scan.json) (the `--json` output with `--all-states`).

## Requirements

Python 3.9 or newer.

## Installation

```
https://github.com/UrielHRO/TcpScan-Project-.git
cd tcpscan
python tcpscan.py --help
```

## Usage

```
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
| `--no-banner` | Disable banner grabbing (service names then come from the port number only) | off |
| `--json FILE` | Save results as JSON | not saved |
| `--md FILE` | Save a Markdown report | not saved |
| `--all-states` | Include closed and filtered ports in the JSON | open only |
| `-q`, `--quiet` | Do not print open ports while scanning | off |

Exit codes: `0` on success, `2` for invalid arguments, `1` if the host cannot be resolved, `130` if interrupted with Ctrl+C.

## Project layout

| Path | Purpose |
|---|---|
| `tcpscan.py` | The scanner |
| `lab_server.py` | Local test lab and automated check for the scanner |
| `examples/` | Real output of a scan against the lab |
| `LICENSE` | MIT license |
| `README.md` | This file |

## Testing

`lab_server.py` starts five fake services on `127.0.0.1` (it never binds to any other address) and knows exactly what the scanner should find.

| Port | Behavior |
|---|---|
| 9021 | Announces an FTP banner |
| 9022 | Announces an SSH banner |
| 9025 | Announces an SMTP banner |
| 9080 | Answers an HTTP request with 200 OK |
| 9090 | Accepts the connection and never replies |

The other scanned ports (9020, 9023, 9024, 9026 to 9030) have nothing listening and must come back as `closed`.

### Automated check

```
python lab_server.py --verify
```

It starts the lab, runs the scanner against it twice (with and without banner grabbing), compares the results with the expected ones and exits with code 0 only if everything matches. Output on Linux:

```
[PASS] scanner exits with code 0  (exit 0)
[PASS] open ports match the lab exactly  (expected [9021, 9022, 9025, 9080, 9090], got [9021, 9022, 9025, 9080, 9090])
[PASS] all other scanned ports reported as closed  (8 of 8)
[PASS] banner on 9021 (fake FTP)  (got '220 lab-ftpd ready')
[PASS] banner on 9022 (fake SSH)  (got 'SSH-2.0-OpenSSH_8.9p1 lab')
[PASS] banner on 9025 (fake SMTP)  (got '220 mail.lab ESMTP ready')
[PASS] banner on 9080 (fake HTTP)  (got 'HTTP/1.1 200 OK')
[PASS] banner on 9090 (silent)  (got '')
[PASS] service on 9021 identified from banner  (got 'ftp' via 'banner')
[PASS] service on 9022 identified from banner  (got 'ssh' via 'banner')
[PASS] service on 9025 identified from banner  (got 'smtp' via 'banner')
[PASS] service on 9080 identified from banner  (got 'http' via 'banner')
[PASS] summary counts are consistent  ({'open': 5, 'closed': 8, 'filtered': 0})
[PASS] --no-banner returns no banners
[PASS] --no-banner never names a service from a banner

15/15 checks passed
```

`lab_server.py` looks for `tcpscan.py` in its own folder. Use `--scanner PATH` if they are in different places.

To watch a scan arrive, run `python lab_server.py` in one terminal (it prints a line per connection) and the scanner in another. Do not run `--verify` while the lab is already running, because both need the same ports.

### Windows timeout behavior

On Windows, a refused connection takes about 2 seconds to be reported, even on localhost. With the default 1 s timeout, the scanner gives up first and reports closed ports as `filtered`. The same lab scanned twice on Windows:

| Command | Result |
|---|---|
| `python tcpscan.py 127.0.0.1 -p 9020-9030,9080,9090` | 5 open, 0 closed, 8 filtered (1.03 s) |
| `python tcpscan.py 127.0.0.1 -p 9020-9030,9080,9090 --timeout 3` | 5 open, 8 closed, 0 filtered (2.04 s) |

Use `--timeout 3` on Windows when you need to tell closed from filtered. Linux reports the refusal immediately, so the default works there. This is why `--verify` runs the scanner with a 3 s timeout.

### Other targets

Suggested targets for real use are your own virtual machines (DVWA, Metasploitable, Juice Shop), TryHackMe rooms and scanme.nmap.org. The Nmap project authorizes scanning that host for testing, with a limit of about a dozen scans per day, and the permission does not cover exploit or denial-of-service testing (see Legal Issues in the references).

## How it works

For each port, a worker thread opens a TCP socket and calls `connect()` with a timeout.

| `connect()` result | Classification | Meaning |
|---|---|---|
| Connection established | `open` | A service is listening |
| `ConnectionRefusedError` | `closed` | The host answered with RST, nothing is listening |
| Timeout or network error | `filtered` | No answer, usually a firewall or a host that is down |

On open ports, the scanner reads whatever the service sends. If nothing arrives, it sends a minimal HTTP request and reads the reply. Only the first line (up to 200 characters) is kept. That line is matched against a short list of banner patterns to name the service. If none matches, the name comes from the port number (`getservbyport`).

## Limitations

- IPv4 only.
- Connect scan only. No SYN scan, which would need raw sockets and root privileges.
- Service identification covers six protocols (ssh, http, ftp, smtp, imap, vnc) and relies on the banner text. It is not version detection. A service with no banner is named from its port number, which is only a guess. Verify manually.
- Banners on TLS ports (443, 993, 995) are usually empty, because the plain-text probe does not complete a TLS handshake.
- One target per run. No CIDR ranges.
- A connect scan is easy to spot in target logs and may trigger an IDS. There is no stealth technique of any kind.
- With a low timeout on slow networks, open ports can show up as `filtered`. Adjust `--timeout` and `-t` and scan again. See also [Windows timeout behavior](#windows-timeout-behavior).
- A scan of all 65535 ports against a host that drops packets is slow. With the default 100 threads and 1 s timeout it takes roughly 11 minutes.

## Comparison with nmap

nmap is much faster, more accurate and far more complete (SYN scan, version detection, scripting engine, IPv6, OS detection). This project does not try to replace it. It exists to show, in a few hundred lines, what happens during a TCP scan and how to structure usable report output.

## References

- Nmap Network Scanning, [TCP Connect Scan (`-sT`)](https://nmap.org/book/scan-methods-connect-scan.html).
- Nmap Network Scanning, [TCP SYN (Stealth) Scan (`-sS`)](https://nmap.org/book/synscan.html), the half-open scan this project does not implement.
- Nmap Network Scanning, [Legal Issues](https://nmap.org/book/legal-issues.html), including the rules for scanme.nmap.org.
- Python docs, [`concurrent.futures`](https://docs.python.org/3/library/concurrent.futures.html), [`socket`](https://docs.python.org/3/library/socket.html) and [`socketserver`](https://docs.python.org/3/library/socketserver.html).
