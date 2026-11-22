# TCP scan report: 127.0.0.1

- Target: `127.0.0.1` (127.0.0.1)
- Started (UTC): 2026-11-22T13:17:38+00:00
- Duration: 0.76 s
- Ports scanned: 13 (threads: 100, timeout: 3.0 s)
- Summary: 5 open, 8 closed, 0 filtered

## Open ports

| Port | Service | Banner |
|---|---|---|
| 9021/tcp | ftp | 220 lab-ftpd ready |
| 9022/tcp | ssh | SSH-2.0-OpenSSH_8.9p1 lab |
| 9025/tcp | smtp | 220 mail.lab ESMTP ready |
| 9080/tcp | http | HTTP/1.1 200 OK |
| 9090/tcp | unknown |  |

## Notes

- Connect scan (full TCP handshake). `filtered` ports mean a timeout, usually a firewall or a host that is down.
- The service name comes from the banner when it matches a known signature, otherwise from the port number, which is only a guess. The JSON output has a `service_source` field with the origin. Verify manually.
