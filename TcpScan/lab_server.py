#!/usr/bin/env python3
"""
lab_server: local test lab for tcpscan.

Starts fake services on 127.0.0.1 so the scanner can be checked against
a known ground truth.

    python lab_server.py            start the services and keep them running
    python lab_server.py --verify   start them, run tcpscan and check the results

Manual use, two terminals:
    terminal 1: python lab_server.py
    terminal 2: python tcpscan.py 127.0.0.1 -p 9020-9030,9080,9090 --timeout 3
"""

import argparse
import json
import socketserver
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HOST = "127.0.0.1"  # never bind to anything else
SCAN_PORTS = "9020-9030,9080,9090"
VERBOSE = True


def log(msg: str) -> None:
    if VERBOSE:
        print(msg, flush=True)


class LabHandler(socketserver.BaseRequestHandler):
    def setup(self) -> None:
        log(f"[lab] connection on {self.server.server_address[1]} "
            f"from {self.client_address[0]}")


class BannerHandler(LabHandler):
    """Announces a fixed banner as soon as the client connects."""

    def handle(self) -> None:
        try:
            self.request.sendall(SERVICES[self.server.server_address[1]][2])
            self.request.settimeout(1.0)
            self.request.recv(1024)
        except OSError:
            pass


class HttpHandler(LabHandler):
    """Replies to any request with an empty 200 response."""

    def handle(self) -> None:
        try:
            self.request.settimeout(2.0)
            self.request.recv(1024)
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nServer: lab-httpd/1.0\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        except OSError:
            pass


class SilentHandler(LabHandler):
    """Accepts the connection, reads the client's data and never replies."""

    def handle(self) -> None:
        try:
            self.request.settimeout(3.0)
            self.request.recv(1024)
        except OSError:
            pass


class LabServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# port -> (label, handler, banner announced on connect)
SERVICES = {
    9021: ("fake FTP", BannerHandler, b"220 lab-ftpd ready\r\n"),
    9022: ("fake SSH", BannerHandler, b"SSH-2.0-OpenSSH_8.9p1 lab\r\n"),
    9025: ("fake SMTP", BannerHandler, b"220 mail.lab ESMTP ready\r\n"),
    9080: ("fake HTTP", HttpHandler, None),
    9090: ("silent", SilentHandler, None),
}

# Banner prefix the scanner should report for each open port.
EXPECTED_BANNERS = {
    9021: "220 lab-ftpd",
    9022: "SSH-2.0-OpenSSH_8.9p1",
    9025: "220 mail.lab",
    9080: "HTTP/1.1 200 OK",
    9090: "",
}

# Service the scanner should name from the banner. 9090 is left out: with no
# banner the name falls back to the OS port table, which varies by system.
EXPECTED_SERVICES = {
    9021: "ftp",
    9022: "ssh",
    9025: "smtp",
    9080: "http",
}


def start_services() -> list[LabServer]:
    servers = []
    for port, (_, handler, _) in SERVICES.items():
        try:
            srv = LabServer((HOST, port), handler)
        except OSError as exc:
            stop_services(servers)
            raise SystemExit(f"error: could not bind {HOST}:{port}: {exc}")
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
    return servers


def stop_services(servers: list[LabServer]) -> None:
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def run_scanner(scanner: Path, json_path: Path, extra: list[str]) -> int:
    # 3 s timeout on purpose: Windows takes about 2 s to report a refused
    # connection, even on localhost, and a shorter timeout turns closed ports
    # into "filtered". Linux refuses instantly, so it costs nothing there.
    cmd = [
        sys.executable, "-I", str(scanner), HOST,
        "-p", SCAN_PORTS, "--timeout", "3.0", "-q",
        "--all-states", "--json", str(json_path), *extra,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60).returncode


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  ({detail})" if detail else ""))
    return ok


def verify(scanner: Path) -> int:
    if not scanner.is_file():
        print(f"error: scanner not found at {scanner}", file=sys.stderr)
        return 2

    scanned = set(range(9020, 9031)) | {9080, 9090}
    open_ports = set(SERVICES)
    closed_ports = scanned - open_ports
    results: list[bool] = []

    servers = start_services()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out1 = Path(tmp) / "with_banner.json"
            code = run_scanner(scanner, out1, [])
            results.append(check("scanner exits with code 0", code == 0, f"exit {code}"))
            data = json.loads(out1.read_text(encoding="utf-8"))
            by_port = {r["port"]: r for r in data["results"]}

            found_open = {p for p, r in by_port.items() if r["state"] == "open"}
            results.append(check(
                "open ports match the lab exactly", found_open == open_ports,
                f"expected {sorted(open_ports)}, got {sorted(found_open)}"))

            found_closed = {p for p, r in by_port.items() if r["state"] == "closed"}
            results.append(check(
                "all other scanned ports reported as closed",
                found_closed == closed_ports,
                f"{len(found_closed)} of {len(closed_ports)}"))

            for port, prefix in EXPECTED_BANNERS.items():
                got = by_port.get(port, {}).get("banner", "<missing>")
                ok = got == "" if prefix == "" else got.startswith(prefix)
                results.append(check(
                    f"banner on {port} ({SERVICES[port][0]})", ok, f"got {got!r}"))

            for port, name in EXPECTED_SERVICES.items():
                r = by_port.get(port, {})
                results.append(check(
                    f"service on {port} identified from banner",
                    r.get("service") == name and r.get("service_source") == "banner",
                    f"got {r.get('service')!r} via {r.get('service_source')!r}"))

            results.append(check(
                "summary counts are consistent",
                data["summary"]["open"] == len(open_ports)
                and data["summary"]["closed"] == len(closed_ports),
                str(data["summary"])))

            out2 = Path(tmp) / "no_banner.json"
            run_scanner(scanner, out2, ["--no-banner"])
            data2 = json.loads(out2.read_text(encoding="utf-8"))
            results.append(check(
                "--no-banner returns no banners",
                all(r["banner"] == "" for r in data2["results"])))
            results.append(check(
                "--no-banner never names a service from a banner",
                all(r["service_source"] != "banner" for r in data2["results"])))
    finally:
        stop_services(servers)

    print(f"\n{sum(results)}/{len(results)} checks passed")
    return 0 if all(results) else 1


def serve() -> int:
    servers = start_services()
    print(f"Lab running on {HOST} (local only). Press Ctrl+C to stop.\n")
    print("Open services:")
    for port, (label, *_) in SERVICES.items():
        print(f"  {port}/tcp  {label}")
    print(f"\nSuggested scan:\n  python tcpscan.py {HOST} -p {SCAN_PORTS} --timeout 3\n")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nstopping lab...")
    finally:
        stop_services(servers)
    return 0


def main() -> int:
    global VERBOSE
    parser = argparse.ArgumentParser(description="Local test lab for tcpscan.")
    parser.add_argument("--verify", action="store_true",
                        help="start the lab, run tcpscan against it and check the results")
    parser.add_argument("--scanner", type=Path,
                        default=Path(__file__).with_name("tcpscan.py"),
                        help="path to tcpscan.py (default: next to this file)")
    args = parser.parse_args()

    if args.verify:
        VERBOSE = False
        return verify(args.scanner)
    return serve()


if __name__ == "__main__":
    sys.exit(main())