#!/usr/bin/env bash
# Local and CI entry point: syntax check, then the lab verification.
# Usage: scripts/ci_check.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== Python version =="
python --version

echo "== Syntax check =="
python -m py_compile TcpScan/tcpscan.py TcpScan/lab_server.py

echo "== Lab verification (15 checks) =="
python TcpScan/lab_server.py --verify
