from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest

import bugbounty_ctf.advanced_tests as advanced
from bugbounty_ctf.advanced_tests import detect_defenses
from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.scope import OutOfScopeError, ScopeGuard


@dataclass(frozen=True, slots=True)
class _SeenRequest:
    path: str
    scanner_header: str | None
    cookie_header: str | None


@dataclass(frozen=True, slots=True)
class _DefenseServer:
    url: str
    seen: list[_SeenRequest]


@pytest.fixture
def defense_server() -> Iterator[_DefenseServer]:
    seen: list[_SeenRequest] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append(
                _SeenRequest(
                    path=self.path,
                    scanner_header=self.headers.get("X-Scanner-Header"),
                    cookie_header=self.headers.get("Cookie"),
                )
            )
            query = parse_qs(urlparse(self.path).query)
            body = query.get("q", ["ok"])[0].encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield _DefenseServer(url=f"http://127.0.0.1:{server.server_port}/", seen=seen)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _scanner_for(url: str, guard: ScopeGuard) -> SecurityScanner:
    return SecurityScanner(
        url,
        db=ScannerDB(":memory:"),
        scope=guard,
        headers={"X-Scanner-Header": "scanner-header"},
        timeout=1,
    )


def test_detect_defenses_with_scanner_checks_scope_before_first_request(
    defense_server: _DefenseServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: the server is reachable, but the scanner scope allows only 127.0.0.1.
    monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)
    out_of_scope_url = defense_server.url.replace("127.0.0.1", "localhost")
    scanner = _scanner_for(
        out_of_scope_url,
        ScopeGuard(["127.0.0.1"], allow_subdomains=False),
    )

    # When / Then: detect_defenses must use scanner._make_request and hard-stop before I/O.
    with pytest.raises(OutOfScopeError):
        detect_defenses(out_of_scope_url, paths=["/"], scanner=scanner)
    assert defense_server.seen == []


def test_detect_defenses_with_scanner_preserves_headers_cookies_and_request_count(
    defense_server: _DefenseServer,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: an in-scope scanner carries request policy state on its session.
    monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)
    scanner = _scanner_for(
        defense_server.url,
        ScopeGuard(["127.0.0.1"], allow_subdomains=False),
    )
    scanner.session.cookies.set("scanner_cookie", "scanner-cookie")

    # When: the full defense workflow runs through the supplied scanner.
    result = detect_defenses(defense_server.url, paths=["/"], scanner=scanner)

    # Then: every probe uses scanner session state and the 37-request workflow remains intact.
    assert result["rate_limit"] == "No 429 in 20 burst requests"
    assert len(defense_server.seen) == 37
    assert {request.scanner_header for request in defense_server.seen} == {"scanner-header"}
    assert {
        "scanner_cookie=scanner-cookie" in (request.cookie_header or "")
        for request in defense_server.seen
    } == {True}
