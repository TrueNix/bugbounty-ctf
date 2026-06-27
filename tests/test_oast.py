"""Tests for the OAST out-of-band collaborator and blind-vuln detection."""

from __future__ import annotations

import contextlib
import re
from typing import Any, ClassVar

import requests

from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.oast import OASTServer
from bugbounty_ctf.oast import test_blind_rce as run_blind_rce
from bugbounty_ctf.oast import test_blind_ssrf as run_blind_ssrf
from bugbounty_ctf.oast import test_blind_xxe as run_blind_xxe


def _scanner() -> SecurityScanner:
    return SecurityScanner("http://target.test/", db=ScannerDB(":memory:"))


class _R:
    status_code = 200
    text = "ok"
    headers: ClassVar[dict[str, str]] = {}


class TestOASTServer:
    def test_records_get_callback(self) -> None:
        with OASTServer() as oast:
            token = oast.new_token()
            requests.get(oast.payload_url(token), timeout=2)
            assert oast.received(token)
            hits = oast.interactions(token)
            assert hits and hits[0]["method"] == "GET" and token in hits[0]["path"]

    def test_wait_for_true_after_hit(self) -> None:
        with OASTServer() as oast:
            token = oast.new_token()
            requests.get(oast.payload_url(token), timeout=2)
            assert oast.wait_for(token, timeout=2)

    def test_no_callback_is_not_received(self) -> None:
        with OASTServer() as oast:
            assert not oast.received("never")
            assert not oast.wait_for("never", timeout=0.3)

    def test_tokens_are_isolated(self) -> None:
        with OASTServer() as oast:
            t1, t2 = oast.new_token("a"), oast.new_token("b")
            requests.get(oast.payload_url(t1), timeout=2)
            assert oast.received(t1)
            assert not oast.received(t2)

    def test_token_matched_in_body(self) -> None:
        with OASTServer() as oast:
            token = oast.new_token()
            requests.post(oast.payload_url("x"), data=token.encode(), timeout=2)
            assert oast.received(token)

    def test_ephemeral_port_assigned(self) -> None:
        with OASTServer() as oast:
            assert oast.port > 0


def _fetch_from(value: str) -> None:
    """Simulate a server-side fetch of any URL found in an injected value."""
    m = re.search(r"https?://[^\s`)\"']+", value)
    if m:
        with contextlib.suppress(requests.RequestException):
            requests.get(m.group(0), timeout=2)


class TestBlindDetection:
    def test_blind_ssrf_confirmed(self) -> None:
        sc = _scanner()
        with OASTServer() as oast:

            def fake(method: str, url: str, **kw: Any) -> _R:
                data = kw.get("data") or kw.get("params") or {}
                _fetch_from(str(data.get("url", "")))
                return _R()

            sc._make_request = fake  # type: ignore[method-assign]
            res = run_blind_ssrf(
                "http://target.test/fetch", scanner=sc, oast=oast, param_name="url", timeout=3
            )
            assert res["vulnerable"] is True
            assert sc.findings and sc.findings[0]["type"] == "blind_ssrf"
            assert sc.findings[0]["source"] == "oast"

    def test_blind_ssrf_not_vulnerable(self) -> None:
        sc = _scanner()
        with OASTServer() as oast:
            sc._make_request = lambda *a, **k: _R()  # type: ignore[method-assign]
            res = run_blind_ssrf("http://target.test/fetch", scanner=sc, oast=oast, timeout=0.5)
            assert res["vulnerable"] is False
            assert sc.findings == []

    def test_blind_rce_confirmed(self) -> None:
        sc = _scanner()
        with OASTServer() as oast:

            def fake(method: str, url: str, **kw: Any) -> _R:
                data = kw.get("params") or kw.get("data") or {}
                _fetch_from(str(data.get("input", "")))
                return _R()

            sc._make_request = fake  # type: ignore[method-assign]
            res = run_blind_rce(
                "http://target.test/ping", scanner=sc, oast=oast, param_name="input", timeout=3
            )
            assert res["vulnerable"] is True

    def test_blind_xxe_confirmed(self) -> None:
        sc = _scanner()
        with OASTServer() as oast:

            def fake(method: str, url: str, **kw: Any) -> _R:
                body = kw.get("data", "")
                m = re.search(r'SYSTEM "([^"]+)"', body if isinstance(body, str) else "")
                if m:
                    _fetch_from(m.group(1))
                return _R()

            sc._make_request = fake  # type: ignore[method-assign]
            res = run_blind_xxe("http://target.test/xml", scanner=sc, oast=oast, timeout=3)
            assert res["vulnerable"] is True
