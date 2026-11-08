#!/usr/bin/env python3
"""
tcpscan: TCP connect port scanner with banner grabbing.

Study project. Only use it against targets you own or have explicit
authorization to test (your own lab, HTB, TryHackMe, scanme.nmap.org).

Examples:
    python tcpscan.py 127.0.0.1 -p 1-1024
    python tcpscan.py scanme.nmap.org -p top --json out.json --md report.md
    python tcpscan.py 10.10.10.5 -p 22,80,443,8080 -t 200 --timeout 0.8
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017,
]

# HTTP servers stay silent until they get a request, so probe them right away.
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}

MAX_BANNER_LEN = 200


def parse_ports(spec: str) -> list[int]:
    """Turn '22,80,1000-1010', 'top' or 'all' into a sorted list of ports."""
    spec = spec.strip().lower()
    if spec == "top":
        return sorted(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, _, end_s = part.partition("-")
            start, end = int(start_s), int(end_s)
            if start > end:
                raise ValueError(f"invalid range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    if not ports:
        raise ValueError("no ports given")
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket, port: int, host: str, timeout: float) -> str:
    """Return the first line the service sends, or an empty string."""
    probe = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: tcpscan\r\n\r\n".encode()
    data = b""
    try:
        # SSH, FTP and SMTP announce themselves, so listen first on non-HTTP ports.
        if port not in HTTP_PORTS:
            sock.settimeout(timeout / 2)
            try:
                data = sock.recv(1024)
            except socket.timeout:
                pass
        # Still nothing: try an HTTP request.
        if not data:
            sock.settimeout(timeout)
            sock.sendall(probe)
            data = sock.recv(1024)
    except OSError:
        pass
    text = data.decode("utf-8", errors="replace").strip()
    first_line = text.splitlines()[0] if text else ""
    return first_line[:MAX_BANNER_LEN]


def scan_port(ip: str, host: str, port: int, timeout: float, banner: bool,
              banner_timeout: float) -> dict:
    result = {"port": port, "state": "filtered", "service": "", "banner": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
    except ConnectionRefusedError:
        result["state"] = "closed"
    except OSError:
        pass  # timeout, no route to host, etc.: stays "filtered"
    else:
        result["state"] = "open"
        result["service"] = service_name(port)
        if banner:
            result["banner"] = grab_banner(sock, port, host, banner_timeout)
    finally:
        sock.close()
    return result


def run_scan(host: str, ports: list[int], threads: int, timeout: float,
             banner: bool, banner_timeout: float, quiet: bool) -> dict:
    try:
        ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except socket.gaierror as exc:
        raise SystemExit(f"error: could not resolve '{host}': {exc}")

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futures = []
        try:
            for p in ports:
                futures.append(
                    pool.submit(scan_port, ip, host, p, timeout, banner, banner_timeout)
                )
            for fut in as_completed(futures):
                res = fut.result()
                results.append(res)
                if res["state"] == "open" and not quiet:
                    extra = f"  {res['banner']}" if res["banner"] else ""
                    print(f"[+] {res['port']}/tcp open ({res['service']}){extra}")
        except KeyboardInterrupt:
            # Drop the queued ports so leaving the pool does not scan them all.
            for fut in futures:
                fut.cancel()
            raise

    results.sort(key=lambda r: r["port"])
    return {
        "target": host,
        "ip": ip,
        "started_utc": started.isoformat(timespec="seconds"),
        "duration_s": round(time.monotonic() - t0, 2),
        "settings": {
            "ports_scanned": len(ports),
            "threads": threads,
            "timeout_s": timeout,
            "banner_grab": banner,
        },
        "summary": {
            "open": sum(r["state"] == "open" for r in results),
            "closed": sum(r["state"] == "closed" for r in results),
            "filtered": sum(r["state"] == "filtered" for r in results),
        },
        "results": results,
    }


def write_json(report: dict, path: str, only_open: bool) -> None:
    data = dict(report)
    if only_open:
        data["results"] = [r for r in report["results"] if r["state"] == "open"]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def write_markdown(report: dict, path: str) -> None:
    s, cfg = report["summary"], report["settings"]
    lines = [
        f"# TCP scan report: {report['target']}",
        "",
        f"- Target: `{report['target']}` ({report['ip']})",
        f"- Started (UTC): {report['started_utc']}",
        f"- Duration: {report['duration_s']} s",
        f"- Ports scanned: {cfg['ports_scanned']} "
        f"(threads: {cfg['threads']}, timeout: {cfg['timeout_s']} s)",
        f"- Summary: {s['open']} open, {s['closed']} closed, {s['filtered']} filtered",
        "",
        "## Open ports",
        "",
    ]
    open_ports = [r for r in report["results"] if r["state"] == "open"]
    if open_ports:
        lines += ["| Port | Service | Banner |", "|---|---|---|"]
        for r in open_ports:
            lines.append(
                f"| {r['port']}/tcp | {md_escape(r['service'])} | {md_escape(r['banner'])} |"
            )
    else:
        lines.append("No open ports found.")
    lines += [
        "",
        "## Notes",
        "",
        "- Connect scan (full TCP handshake). `filtered` ports mean a timeout, "
        "usually a firewall or a host that is down.",
        "- The service name comes from the port number, not from fingerprinting. "
        "Verify manually.",
        "",
    ]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="TCP connect port scanner with banner grabbing (study project).",
        epilog="Only use against authorized targets.",
    )
    p.add_argument("host", help="target hostname or IPv4 address")
    p.add_argument("-p", "--ports", default="1-1024",
                   help="ports: '22,80,443', '1-1024', 'top' or 'all' (default: 1-1024)")
    p.add_argument("-t", "--threads", type=int, default=100,
                   help="concurrent connections (default: 100)")
    p.add_argument("--timeout", type=float, default=1.0,
                   help="connection timeout in seconds (default: 1.0)")
    p.add_argument("--banner-timeout", type=float, default=1.5,
                   help="banner wait time in seconds (default: 1.5)")
    p.add_argument("--no-banner", action="store_true", help="disable banner grabbing")
    p.add_argument("--json", metavar="FILE", help="save results as JSON")
    p.add_argument("--md", metavar="FILE", help="save a Markdown report")
    p.add_argument("--all-states", action="store_true",
                   help="include closed/filtered ports in the JSON (default: open only)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="do not print open ports while scanning")
    return p


def main() -> int:
    args = build_parser().parse_args()

    if args.threads < 1 or args.timeout <= 0 or args.banner_timeout <= 0:
        print("error: threads, timeout and banner-timeout must be positive",
              file=sys.stderr)
        return 2
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print("Warning: only scan targets you own or are authorized to test.",
          file=sys.stderr)
    print(f"Scanning {args.host} ({len(ports)} ports)...", file=sys.stderr)

    try:
        report = run_scan(args.host, ports, args.threads, args.timeout,
                          not args.no_banner, args.banner_timeout, args.quiet)
    except KeyboardInterrupt:
        print("\ninterrupted by user", file=sys.stderr)
        return 130

    s = report["summary"]
    print(f"\nDone in {report['duration_s']} s: "
          f"{s['open']} open, {s['closed']} closed, {s['filtered']} filtered.")

    if args.json:
        write_json(report, args.json, only_open=not args.all_states)
        print(f"JSON saved to {args.json}")
    if args.md:
        write_markdown(report, args.md)
        print(f"Report saved to {args.md}")
    return 0


if __name__ == "__main__":
    sys.exit(main())