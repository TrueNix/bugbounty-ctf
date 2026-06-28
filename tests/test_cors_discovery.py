"""Tests for the CORS and content-discovery quick tests."""

from __future__ import annotations

from typing import Any

from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.quick_tests import discover_content
from bugbounty_ctf.quick_tests import test_cors as run_cors
from bugbounty_ctf.quick_tests import test_open_redirect as run_open_redirect


class _Resp:
    def __init__(
        self, status: int = 200, text: str = "ok", headers: dict[str, str] | None = None
    ) -> None:
        self.status_code = status
        self.text = text
        self.headers = headers or {}


def _scanner() -> SecurityScanner:
    return SecurityScanner("http://target.test/", db=ScannerDB(":memory:"))


class TestCORS:
    def test_reflected_origin_with_credentials_is_critical(self) -> None:
        sc = _scanner()

        def fake(method: str, url: str, **kwargs: Any) -> _Resp:
            origin = kwargs.get("headers", {}).get("Origin", "")
            return _Resp(
                headers={
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                }
            )

        sc._make_request = fake  # type: ignore[method-assign]
        results = run_cors("http://target.test/api", scanner=sc)
        assert any(r["severity"] == "critical" for r in results)

    def test_null_origin_trusted(self) -> None:
        sc = _scanner()

        def fake(method: str, url: str, **kwargs: Any) -> _Resp:
            origin = kwargs.get("headers", {}).get("Origin", "")
            acao = "null" if origin == "null" else ""
            return _Resp(headers={"Access-Control-Allow-Origin": acao})

        sc._make_request = fake  # type: ignore[method-assign]
        results = run_cors("http://target.test/api", scanner=sc)
        assert any(r["test"] == "null" and r["severity"] == "medium" for r in results)

    def test_no_cors_headers_means_no_findings(self) -> None:
        sc = _scanner()
        sc._make_request = lambda *a, **k: _Resp()  # type: ignore[method-assign]
        assert run_cors("http://target.test/api", scanner=sc) == []


class TestContentDiscovery:
    def test_finds_non_404_paths(self) -> None:
        sc = _scanner()

        def fake(method: str, url: str, **kwargs: Any) -> _Resp:
            if url.endswith("/admin"):
                return _Resp(200, "admin panel")
            return _Resp(404, "not found")

        sc._make_request = fake  # type: ignore[method-assign]
        results = discover_content(
            "http://target.test/", scanner=sc, wordlist=["admin", "missing", "ghost"]
        )
        paths = {r["path"] for r in results}
        assert "admin" in paths
        assert "missing" not in paths

    def test_concurrent_and_sequential_agree(self) -> None:
        # workers>1 (default) must return the same set as a sequential scan.
        def make_scanner() -> SecurityScanner:
            sc = _scanner()

            def fake(method: str, url: str, **kwargs: Any) -> _Resp:
                return _Resp(200, "hit") if url.rstrip("/").endswith(("/a", "/c")) else _Resp(404)

            sc._make_request = fake  # type: ignore[method-assign]
            return sc

        words = ["a", "b", "c", "d", "e"]
        seq = discover_content("http://t.test/", scanner=make_scanner(), wordlist=words, workers=1)
        con = discover_content("http://t.test/", scanner=make_scanner(), wordlist=words, workers=8)
        assert {r["path"] for r in seq} == {r["path"] for r in con} == {"a", "c"}

    def test_filters_catch_all_signature(self) -> None:
        # Simulate a PHP dev server: every path returns 200 with identical
        # length. The dominant signature must be filtered out.
        sc = _scanner()
        sc._make_request = lambda *a, **k: _Resp(200, "x" * 500)  # type: ignore[method-assign]
        words = [f"w{i}" for i in range(40)]
        results = discover_content("http://target.test/", scanner=sc, wordlist=words)
        assert results == []

    def test_extensions_are_appended(self) -> None:
        sc = _scanner()
        seen: list[str] = []

        def fake(method: str, url: str, **kwargs: Any) -> _Resp:
            seen.append(url)
            return _Resp(404)

        sc._make_request = fake  # type: ignore[method-assign]
        discover_content(
            "http://target.test/", scanner=sc, wordlist=["backup"], extensions=["bak", ".zip"]
        )
        assert any(u.endswith("/backup.bak") for u in seen)
        assert any(u.endswith("/backup.zip") for u in seen)


class TestOpenRedirect:
    def test_detects_redirect_to_evil_host(self) -> None:
        sc = _scanner()

        def fake(method: str, url: str, **kwargs: Any) -> _Resp:
            payload = kwargs.get("params", {}).get("next", "")
            # Server naively 302s to whatever ?next= contains.
            return _Resp(302, headers={"Location": payload})

        sc._make_request = fake  # type: ignore[method-assign]
        results = run_open_redirect(
            "http://target.test/login", scanner=sc, params=["next"], evil_host="evil.example"
        )
        assert any(r["param"] == "next" for r in results)

    def test_same_site_redirect_not_flagged(self) -> None:
        sc = _scanner()
        # Always redirects within the site → not an open redirect.
        sc._make_request = lambda *a, **k: _Resp(  # type: ignore[method-assign]
            302, headers={"Location": "https://target.test/home"}
        )
        results = run_open_redirect(
            "http://target.test/login", scanner=sc, params=["next"], evil_host="evil.example"
        )
        assert results == []

    def test_non_redirect_status_ignored(self) -> None:
        sc = _scanner()
        sc._make_request = lambda *a, **k: _Resp(200, "ok")  # type: ignore[method-assign]
        assert run_open_redirect("http://target.test/login", scanner=sc, params=["next"]) == []
