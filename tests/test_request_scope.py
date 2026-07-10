from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.scope import OutOfScopeError, ScopeGuard


@dataclass(frozen=True, slots=True)
class SeenRequest:
    method: str
    path: str
    body: bytes
    cookie: str


@dataclass(frozen=True, slots=True)
class LocalHTTPServer:
    server: ThreadingHTTPServer
    thread: Thread

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    @property
    def localhost_url(self) -> str:
        _, port = self.server.server_address
        return f"http://localhost:{port}"


HandlerFunc = Callable[[BaseHTTPRequestHandler, bytes], None]


@contextmanager
def local_server(handler_func: HandlerFunc) -> Iterator[LocalHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def log_message(self, format: str, *args: object) -> None:
            return

        def _handle(self) -> None:
            content_length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(content_length) if content_length else b""
            handler_func(self, body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield LocalHTTPServer(server=server, thread=thread)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def send_text(handler: BaseHTTPRequestHandler, status: int, body: str = "") -> None:
    payload = body.encode()
    handler.send_response(status)
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def scoped_scanner(base_url: str) -> SecurityScanner:
    return SecurityScanner(
        base_url,
        db=ScannerDB(":memory:"),
        scope=ScopeGuard(["127.0.0.1"], allow_subdomains=False),
    )


def test_make_request_blocks_307_post_redirect_before_denied_host_receives_body() -> None:
    destination_hits: list[SeenRequest] = []

    def destination_handler(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        destination_hits.append(
            SeenRequest(
                method=handler.command,
                path=handler.path,
                body=body,
                cookie=handler.headers.get("Cookie", ""),
            )
        )
        send_text(handler, 200, "denied")

    with local_server(destination_handler) as destination:
        origin_hits: list[bytes] = []

        def origin_handler(handler: BaseHTTPRequestHandler, body: bytes) -> None:
            origin_hits.append(body)
            handler.send_response(307)
            handler.send_header("Location", f"{destination.localhost_url}/sink")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        with local_server(origin_handler) as origin:
            scanner = scoped_scanner(origin.url)

            with pytest.raises(OutOfScopeError, match="localhost"):
                scanner._make_request("POST", f"{origin.url}/submit", data="payload=secret")

    assert origin_hits == [b"payload=secret"]
    assert destination_hits == []


@pytest.mark.parametrize(
    ("status_code", "expected_method", "expected_body"),
    [
        (301, "GET", b""),
        (302, "GET", b""),
        (303, "GET", b""),
        (307, "POST", b"payload=secret"),
        (308, "POST", b"payload=secret"),
    ],
)
def test_make_request_preserves_requests_redirect_semantics_inside_scope(
    status_code: int,
    expected_method: str,
    expected_body: bytes,
) -> None:
    destination_hits: list[SeenRequest] = []

    def destination_handler(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        seen = SeenRequest(
            method=handler.command,
            path=handler.path,
            body=body,
            cookie=handler.headers.get("Cookie", ""),
        )
        destination_hits.append(seen)
        send_text(handler, 200, f"{seen.method}:{seen.body.decode()}:{seen.cookie}")

    with local_server(destination_handler) as destination:

        def origin_handler(handler: BaseHTTPRequestHandler, body: bytes) -> None:
            handler.send_response(status_code)
            handler.send_header("Location", f"{destination.url}/sink")
            handler.send_header("Set-Cookie", "scan=ok")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        with local_server(origin_handler) as origin:
            scanner = scoped_scanner(origin.url)

            response = scanner._make_request(
                "POST",
                f"{origin.url}/submit",
                data="payload=secret",
            )

    assert response.status_code == 200
    assert len(response.history) == 1
    assert response.history[0].status_code == status_code
    assert destination_hits == [
        SeenRequest(
            method=expected_method,
            path="/sink",
            body=expected_body,
            cookie="scan=ok",
        )
    ]


def test_make_request_without_scope_keeps_requests_redirect_compatibility() -> None:
    destination_hits: list[str] = []

    def destination_handler(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        destination_hits.append(handler.path)
        send_text(handler, 200, "ok")

    with local_server(destination_handler) as destination:

        def origin_handler(handler: BaseHTTPRequestHandler, body: bytes) -> None:
            handler.send_response(302)
            handler.send_header("Location", f"{destination.localhost_url}/open")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        with local_server(origin_handler) as origin:
            scanner = SecurityScanner(origin.url, db=ScannerDB(":memory:"))

            response = scanner._make_request("GET", f"{origin.url}/start")

    assert response.status_code == 200
    assert response.text == "ok"
    assert destination_hits == ["/open"]


def test_map_surface_rejects_absolute_out_of_scope_start_url_before_transmission() -> None:
    destination_hits: list[str] = []

    def destination_handler(handler: BaseHTTPRequestHandler, body: bytes) -> None:
        destination_hits.append(handler.path)
        send_text(handler, 200, "<html></html>")

    with local_server(destination_handler) as destination:

        def origin_handler(handler: BaseHTTPRequestHandler, body: bytes) -> None:
            send_text(handler, 200, "<html></html>")

        with local_server(origin_handler) as origin:
            scanner = scoped_scanner(origin.url)

            with pytest.raises(OutOfScopeError, match="localhost"):
                scanner.map_surface(f"{destination.localhost_url}/surface")

    assert destination_hits == []
