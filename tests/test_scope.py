"""Tests for the scope guard and its scanner integration."""

from __future__ import annotations

import pytest

from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.scope import OutOfScopeError, ScopeGuard


class TestScopeGuard:
    def test_top_level_import_matches_documented_quick_start(self) -> None:
        from bugbounty_ctf import ScopeGuard as PublicScopeGuard

        assert PublicScopeGuard is ScopeGuard

    def test_exact_host_allowed(self) -> None:
        guard = ScopeGuard(["api.example.com"], allow_subdomains=False)
        assert guard.is_allowed("https://api.example.com/x")
        assert not guard.is_allowed("https://other.example.com/x")

    def test_wildcard_matches_subdomains(self) -> None:
        guard = ScopeGuard(["*.example.com"])
        assert guard.is_allowed("https://app.example.com/")
        assert guard.is_allowed("https://deep.app.example.com/")
        assert guard.is_allowed("https://example.com/")  # apex matches *. too
        assert not guard.is_allowed("https://evil.com/")

    def test_apex_implies_subdomains_when_enabled(self) -> None:
        guard = ScopeGuard(["example.com"], allow_subdomains=True)
        assert guard.is_allowed("https://www.example.com/")
        assert guard.is_allowed("https://example.com/")

    def test_apex_excludes_subdomains_when_disabled(self) -> None:
        guard = ScopeGuard(["example.com"], allow_subdomains=False)
        assert guard.is_allowed("https://example.com/")
        assert not guard.is_allowed("https://www.example.com/")

    def test_lookalike_suffix_not_matched(self) -> None:
        guard = ScopeGuard(["example.com"])
        assert not guard.is_allowed("https://notexample.com/")
        assert not guard.is_allowed("https://example.com.evil.com/")

    def test_empty_allowlist_denies_all(self) -> None:
        guard = ScopeGuard([])
        assert not guard.is_allowed("https://anything.com/")

    def test_port_and_credentials_ignored(self) -> None:
        guard = ScopeGuard(["example.com"], allow_subdomains=False)
        assert guard.is_allowed("https://user:pass@example.com:8443/x")

    def test_check_raises_out_of_scope(self) -> None:
        guard = ScopeGuard(["example.com"])
        guard.check("https://example.com/ok")  # no raise
        with pytest.raises(OutOfScopeError):
            guard.check("https://evil.com/x")

    def test_accepts_url_entries(self) -> None:
        guard = ScopeGuard(["https://api.example.com/path"], allow_subdomains=False)
        assert guard.is_allowed("https://api.example.com/other")


class TestScannerIntegration:
    def test_in_scope_request_not_blocked(self) -> None:
        guard = ScopeGuard(["target.test"])
        scanner = SecurityScanner("http://target.test/", db=ScannerDB(":memory:"), scope=guard)
        # In-scope: the scope check passes (the request itself fails to connect,
        # which is the retry/fallback path, not an OutOfScopeError).
        resp = scanner._make_request("GET", "http://target.test/")
        assert resp.status_code == 0  # connection failed, but was allowed through

    def test_out_of_scope_request_raises(self) -> None:
        guard = ScopeGuard(["target.test"])
        scanner = SecurityScanner("http://target.test/", db=ScannerDB(":memory:"), scope=guard)
        with pytest.raises(OutOfScopeError):
            scanner._make_request("GET", "http://evil.example/")

    def test_no_guard_allows_anything(self) -> None:
        scanner = SecurityScanner("http://target.test/", db=ScannerDB(":memory:"))
        # No scope configured → no OutOfScopeError (connection just fails).
        resp = scanner._make_request("GET", "http://evil.example/")
        assert resp.status_code == 0
