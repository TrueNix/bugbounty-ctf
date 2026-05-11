#!/usr/bin/env python3
"""
Callback listener for XSS bot / SSRF callback detection.

When testing XSS or SSRF, you need to know if any bot/admin fetches URLs you
inject. This listener logs every request to stdout AND a file, with timestamp
and User-Agent. Run it on your VPN IP (e.g., tun0 = 10.x.x.x) and inject URLs
like http://YOUR_IP:8888/xss-test in your payloads.

Usage:
    python3 callback_listener.py 10.20.10.3 8888
    # Then inject: http://10.20.10.3:8888/callback?payload=xss
    # Check /tmp/callbacks.log for hits

If you see hits from IPs other than your own, a bot is visiting your URLs.
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

LOG_FILE = '/tmp/callbacks.log'

class Handler(BaseHTTPRequestHandler):
    def log_request(self, code='-'):
        ts = datetime.now().isoformat(timespec='seconds')
        ua = self.headers.get('User-Agent', '-')[:80]
        line = f"[{ts}] {self.client_address[0]}:{self.client_address[1]} {self.command} {self.path} UA={ua}"
        print(line, flush=True)
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')

    def do_GET(self):
        self.log_request()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'ok\n')

    def do_POST(self):
        self.log_request()
        ln = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(ln) if ln else b''
        with open(LOG_FILE, 'a') as f:
            f.write(f"  body={body[:500]!r}\n")
        print(f"  body={body[:500]!r}", flush=True)
        self.send_response(200)
        self.end_headers()

    do_PUT = do_POST
    do_DELETE = do_GET
    do_OPTIONS = do_GET

if __name__ == '__main__':
    open(LOG_FILE, 'w').close()  # Clear previous log
    bind = sys.argv[1] if len(sys.argv) > 1 else '0.0.0.0'
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888
    print(f"Callback listener on {bind}:{port}", flush=True)
    print(f"Logging to {LOG_FILE}", flush=True)
    HTTPServer((bind, port), Handler).serve_forever()