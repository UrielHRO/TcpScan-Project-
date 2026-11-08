# TCP scan report: 127.0.0.1

- Target: `127.0.0.1` (127.0.0.1)
- Started (UTC): 2026-11-08T20:15:33+00:00
- Duration: 1.03 s
- Ports scanned: 13 (threads: 100, timeout: 1.0 s)
- Summary: 5 open, 0 closed, 8 filtered

## Open ports

| Port | Service | Banner |
|---|---|---|
| 9021/tcp | unknown | 220 lab-ftpd ready |
| 9022/tcp | unknown | SSH-2.0-OpenSSH_8.9p1 lab |
| 9025/tcp | unknown | 220 mail.lab ESMTP ready |
| 9080/tcp | unknown | HTTP/1.1 200 OK |
| 9090/tcp | unknown |  |

## Notes

- Connect scan (full TCP handshake). `filtered` ports mean a timeout, usually a firewall or a host that is down.
- The service name comes from the port number, not from fingerprinting. Verify manually.
