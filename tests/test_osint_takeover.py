"""Tests for OSINT subdomain-takeover detection."""

from __future__ import annotations

from typing import Any

from bugbounty_ctf.osint import OSINTToolkit


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text
        self.headers: dict[str, str] = {}


class _FakeSession:
    def __init__(self, text: str) -> None:
        self._text = text
        self.headers: dict[str, str] = {}

    def get(self, url: str, **kwargs: Any) -> _Resp:
        return _Resp(self._text)


def _toolkit(body: str) -> OSINTToolkit:
    tk = OSINTToolkit()
    tk.session = _FakeSession(body)  # type: ignore[assignment]
    return tk


class TestSubdomainTakeover:
    def test_github_pages_fingerprint(self) -> None:
        tk = _toolkit("404 — There isn't a GitHub Pages site here.")
        result = tk.check_subdomain_takeover("sub.target.test")
        assert result["vulnerable"]
        assert result["service"] == "GitHub Pages"

    def test_s3_fingerprint(self) -> None:
        tk = _toolkit("<Error><Code>NoSuchBucket</Code></Error>")
        result = tk.check_subdomain_takeover("assets.target.test")
        assert result["vulnerable"]
        assert result["service"] == "AWS S3"

    def test_benign_page_not_flagged(self) -> None:
        tk = _toolkit("<html><body>Welcome to our site</body></html>")
        result = tk.check_subdomain_takeover("www.target.test")
        assert not result["vulnerable"]

    def test_empty_body_not_flagged(self) -> None:
        tk = _toolkit("")
        result = tk.check_subdomain_takeover("dead.target.test")
        assert not result["vulnerable"]
