"""Tests for SecurityScanner — core engine with mocked HTTP via responses library."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses

from bugbounty_ctf.engine import ScannerDB, SecurityScanner, derive_base_url


class TestDeriveBaseUrl:
    """Verify the fix for the old url.rsplit('/', 1)[0] approach."""

    def test_simple_path(self) -> None:
        assert derive_base_url("http://target/login") == "http://target"

    def test_nested_path(self) -> None:
        assert derive_base_url("http://target/api/v1/login") == "http://target"

    def test_with_port(self) -> None:
        assert derive_base_url("https://example.com:8443/path") == "https://example.com:8443"

    def test_root_path(self) -> None:
        assert derive_base_url("http://target/") == "http://target"

    def test_no_path(self) -> None:
        assert derive_base_url("http://target") == "http://target"

    def test_invalid_url_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid URL"):
            derive_base_url("not-a-url")


class TestSecurityScannerInit:
    def test_base_url_strips_trailing_slash(self) -> None:
        scanner = SecurityScanner("http://target/")
        assert scanner.base_url == "http://target"

    def test_default_state_file(self) -> None:
        scanner = SecurityScanner("http://target/")
        assert ".hermes" in scanner.state_file

    def test_custom_state_file(self) -> None:
        scanner = SecurityScanner("http://target/", state_file="/tmp/test_state.json")
        assert scanner.state_file == "/tmp/test_state.json"

    def test_respect_waf_flag(self) -> None:
        scanner = SecurityScanner("http://target/", respect_waf=True)
        assert scanner.respect_waf is True


class TestSecurityScannerMakeRequest:
    @responses.activate
    def test_successful_request_sets_response_time(self) -> None:
        responses.add(responses.GET, "http://target/test", json={"ok": True}, status=200)
        scanner = SecurityScanner("http://target/")
        r = scanner._make_request("GET", "http://target/test")
        assert r.status_code == 200
        assert hasattr(r, "response_time")
        assert r.response_time >= 0.0

    @responses.activate
    def test_request_exception_returns_status_zero(self) -> None:
        # Trigger a connection error by registering a response that raises
        responses.add(
            responses.GET,
            "http://target/fail",
            body=ConnectionError("refused"),
            status=500,
        )
        # We need to use a requests session that will actually fail
        # The responses library intercepts, so let's test with a timeout instead
        # by hitting an endpoint that's not mocked
        scanner = SecurityScanner("http://target/", timeout=1)
        # _make_request catches RequestException and returns status_code=0
        # We simulate by mocking the session.request to raise
        from unittest.mock import patch

        from requests.exceptions import ConnectionError as ReqConnError

        with patch.object(scanner.session, "request", side_effect=ReqConnError("refused")):
            r = scanner._make_request("GET", "http://target/fail")
        assert r.status_code == 0
        assert "Request failed" in r.text


class TestSecurityScannerMapSurface:
    @responses.activate
    def test_map_surface_extracts_forms_any_attribute_order(self) -> None:
        """Verify the form regex fix: action before method."""
        html = """
        <html>
        <body>
            <form action="/login" method="post">
                <input name="username" value="">
                <input name="password" value="">
            </form>
            <form method="get" action="/search">
                <input name="q">
            </form>
        </body>
        </html>
        """
        responses.add(responses.GET, "http://target/", body=html, status=200)
        scanner = SecurityScanner("http://target/")
        surface = scanner.map_surface("/")

        assert surface["status_code"] == 200
        forms = surface["forms"]
        assert len(forms) == 2
        # First form: action before method
        assert forms[0]["method"] == "POST"
        assert forms[0]["action"] == "http://target/login"
        assert len(forms[0]["inputs"]) == 2
        # Second form: method before action
        assert forms[1]["method"] == "GET"
        assert forms[1]["action"] == "http://target/search"

    @responses.activate
    def test_map_surface_extracts_links(self) -> None:
        html = """
        <html>
        <a href="/page1">Page 1</a>
        <a href="/page2">Page 2</a>
        <a href="#section">Skip</a>
        <a href="javascript:void(0)">JS</a>
        </html>
        """
        responses.add(responses.GET, "http://target/", body=html, status=200)
        scanner = SecurityScanner("http://target/")
        surface = scanner.map_surface("/")

        links = surface["links"]
        assert "http://target/page1" in links
        assert "http://target/page2" in links
        assert not any("#section" in link for link in links)
        assert not any("javascript:" in link for link in links)

    @responses.activate
    def test_map_surface_detects_technology(self) -> None:
        responses.add(
            responses.GET,
            "http://target/",
            body="<html>jinja</html>",
            status=200,
            headers={"Server": "nginx/1.21", "X-Powered-By": "PHP/8.1"},
        )
        scanner = SecurityScanner("http://target/")
        surface = scanner.map_surface("/")
        hints = surface["tech_hints"]
        assert "nginx" in hints
        assert "X-Powered-By: PHP/8.1" in hints


class TestSecurityScannerStatePersistence:
    def test_findings_persist_via_db_across_instances(self, tmp_path: Path) -> None:
        # The ScannerDB is the single source of truth: a new SecurityScanner
        # bound to the same DB reloads prior findings on init — no JSON read.
        db = ScannerDB(str(tmp_path / "scanner.db"))
        scanner = SecurityScanner("http://target/", state_file=str(tmp_path / "s.json"), db=db)
        scanner._record_finding("/x", "GET", "'", ["sqli"], ["SQL error"], "sqli")

        scanner2 = SecurityScanner(
            "http://target/",
            state_file=str(tmp_path / "s.json"),
            db=ScannerDB(str(tmp_path / "scanner.db")),
        )
        assert len(scanner2.findings) == 1
        assert scanner2.findings[0]["type"] == "sqli"

    def test_save_snapshot_writes_artifact_not_required_for_persistence(
        self, tmp_path: Path
    ) -> None:
        # save_snapshot writes a derived JSON artifact, but persistence does not
        # depend on it: a fresh scanner reloads from the DB even with no file.
        db_path = str(tmp_path / "scanner.db")
        snap = tmp_path / "snapshot.json"
        scanner = SecurityScanner("http://target/", state_file=str(snap), db=ScannerDB(db_path))
        scanner._record_finding("/x", "GET", "'", ["sqli"], ["SQL error"], "sqli")
        assert not snap.exists()  # _record_finding does NOT write the artifact

        written = scanner.save_snapshot()
        assert written == str(snap)
        assert snap.exists()
        data = json.loads(snap.read_text())
        assert data["base_url"] == "http://target"
        assert any(f["type"] == "sqli" for f in data["findings"])

        # Delete the artifact entirely; the DB still drives persistence.
        snap.unlink()
        scanner3 = SecurityScanner("http://target/", state_file=str(snap), db=ScannerDB(db_path))
        assert len(scanner3.findings) == 1

    def test_reload_picks_up_findings_from_shared_db(self, tmp_path: Path) -> None:
        # Two scanners sharing one ScannerDB see each other's findings after
        # reload() — proves single-store cross-agent feed-forward.
        db = ScannerDB(str(tmp_path / "shared.db"))
        a = SecurityScanner("http://target/", state_file=str(tmp_path / "a.json"), db=db)
        b = SecurityScanner("http://target/", state_file=str(tmp_path / "b.json"), db=db)

        a._record_finding("/login", "POST", "' OR 1=1--", ["sqli"], ["err"], "sqli")
        assert b.findings == []  # not visible until reload

        b.reload()
        assert any(f["type"] == "sqli" and f["endpoint"] == "/login" for f in b.findings)

    def test_reload_tolerates_empty_db(self, tmp_path: Path) -> None:
        # A scanner against a brand-new DB starts with no findings, no error.
        scanner = SecurityScanner(
            "http://target/", state_file=str(tmp_path / "s.json"), db=ScannerDB(":memory:")
        )
        assert scanner.findings == []
        scanner.reload()
        assert scanner.findings == []


class TestSecurityScannerPayloadSet:
    @responses.activate
    def test_run_payload_set_records_findings(self) -> None:
        # Baseline response
        responses.add(responses.GET, "http://target/search", body="normal", status=200)
        # Payload response — triggers SQL error
        responses.add(
            responses.GET,
            "http://target/search",
            body="SQL syntax error",
            status=500,
        )
        # We need different responses for baseline vs payload — use a regex match
        responses.reset()
        # Baseline
        responses.add(
            responses.GET,
            "http://target/search",
            body="normal page",
            status=200,
            match=[responses.matchers.query_param_matcher({"q": "test"})],
        )
        # SQL error payload
        responses.add(
            responses.GET,
            "http://target/search",
            body="SQL syntax error near",
            status=500,
            match=[responses.matchers.query_param_matcher({"q": "'"})],
        )

        scanner = SecurityScanner("http://target/")
        baseline = scanner.get_baseline("GET", "http://target/search", params={"q": "test"})
        results = scanner.run_payload_set(
            baseline, "GET", "http://target/search", {"sqli_test": "'"}, "q"
        )

        assert len(results) == 1
        assert results[0]["analysis"]["interesting"] is True
        assert len(scanner.findings) >= 1
