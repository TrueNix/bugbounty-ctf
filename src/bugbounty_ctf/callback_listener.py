"""Callback listener for XSS bot / SSRF callback detection.

When testing XSS or SSRF, you need to know if any bot/admin fetches URLs you
inject. This listener logs every request to stdout AND a file, with timestamp
and User-Agent. Run it on your VPN IP (e.g., tun0 = 10.x.x.x) and inject URLs
like http://YOUR_IP:8888/xss-test in your payloads.

Usage:
    python3 callback_listener.py 10.20.10.3 8888
    # Then inject: http://10.20.10.3:8888/callback?payload=xss
    # Check /tmp/callbacks.log for hits

If you see hits from IPs other than your own, a bot is visiting your URLs.

Thread-safety fix: log writes are now serialized via a threading.Lock and
the log file is append-only (no truncation on restart) — previous evidence
is preserved.
"""

from __future__ import annotations

import sys
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG_FILE = "/tmp/callbacks.log"
_log_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def _log_request(self) -> None:
        ts = datetime.now().isoformat(timespec="seconds")
        ua = self.headers.get("User-Agent", "-")[:80]
        line = (
            f"[{ts}] {self.client_address[0]}:{self.client_address[1]} "
            f"{self.command} {self.path} UA={ua}"
        )
        print(line, flush=True)
        with _log_lock, open(LOG_FILE, "a") as f:
            f.write(line + "\n")

    def do_GET(self) -> None:
        self._log_request()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_POST(self) -> None:
        self._log_request()
        ln = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(ln) if ln else b""
        body_line = f"  body={body[:500]!r}"
        with _log_lock, open(LOG_FILE, "a") as f:
            f.write(body_line + "\n")
        print(body_line, flush=True)
        self.send_response(200)
        self.end_headers()

    do_PUT = do_POST
    do_DELETE = do_GET
    do_OPTIONS = do_GET


if __name__ == "__main__":
    # Append-only: do NOT truncate — previous evidence matters
    bind = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
    print(f"Callback listener on {bind}:{port}", flush=True)
    print(f"Logging to {LOG_FILE} (append mode)", flush=True)
    HTTPServer((bind, port), Handler).serve_forever()
