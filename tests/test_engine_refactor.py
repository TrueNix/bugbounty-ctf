from __future__ import annotations

import sqlite3

import requests
import responses

from bugbounty_ctf.engine import (
    ScannerDB,
    SecurityScanner,
    _create_findings_table,
    _create_history_tables,
    _create_hypotheses_table,
    _create_observations_table,
    _create_patterns_table,
    _scan_analyze,
    _scan_execute,
    _scan_prepare,
)


def _response(text: str, status_code: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response._content = text.encode()
    return response


def _sqlite_names(conn: sqlite3.Connection, item_type: str) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type = ?", (item_type,)).fetchall()
    return {row[0] for row in rows}


class TestScanHelpers:
    def test_scan_prepare_get_uses_params_and_preserves_request_options(self) -> None:
        prepared = _scan_prepare(
            "http://target/search",
            "GET",
            {"q": "test", "page": "1"},
            {"X-Test": "yes"},
            {"sid": "abc"},
        )

        assert prepared["is_post"] is False
        assert prepared["test_param"] == "q"
        assert prepared["request_kwargs"] == {
            "params": {"q": "test", "page": "1"},
            "headers": {"X-Test": "yes"},
            "cookies": {"sid": "abc"},
        }

    def test_scan_prepare_post_uses_data(self) -> None:
        prepared = _scan_prepare("http://target/login", "POST", {"user": "alice"}, None, None)

        assert prepared["is_post"] is True
        assert prepared["test_param"] == "user"
        assert prepared["request_kwargs"] == {"data": {"user": "alice"}}

    @responses.activate
    def test_scan_execute_uses_scanner_request_path(self) -> None:
        responses.add(
            responses.GET,
            "http://target/search",
            body="ok",
            status=200,
            match=[responses.matchers.query_param_matcher({"q": "test"})],
        )
        scanner = SecurityScanner("http://target/", db=ScannerDB(":memory:"))
        prepared = _scan_prepare("http://target/search", "GET", {"q": "test"}, None, None)

        response = _scan_execute("http://target/search", "GET", prepared, scanner)

        assert response.status_code == 200
        assert response.text == "ok"
        assert hasattr(response, "response_time")

    def test_scan_analyze_records_confirmed_finding(self) -> None:
        scanner = SecurityScanner("http://target/", db=ScannerDB(":memory:"))
        raw = {
            "payload": "single_quote",
            "test_status": 500,
            "analysis": {
                "interesting": True,
                "indicators": ["sql_error"],
                "differences": ["Pattern found: sql_error"],
                "length_diff": 12,
            },
        }
        state = {
            "scanner": scanner,
            "method": "GET",
            "raw": raw,
            "baseline_text": "normal page",
            "payload_value": "'",
            "vuln_type": "sqli",
        }

        result = _scan_analyze(
            "http://target/search",
            _response("You have an error in your SQL syntax", 500),
            state,
        )

        assert result.confirmed is True
        assert result.status_code == 500
        assert result.response_length == len("You have an error in your SQL syntax")
        assert scanner.findings[0]["payload"] == "single_quote"
        assert scanner.findings[0]["type"] == "sqli"


class TestSchemaHelpers:
    def test_schema_helpers_create_tables_and_indexes(self) -> None:
        conn = sqlite3.connect(":memory:")

        _create_findings_table(conn)
        _create_history_tables(conn)
        _create_observations_table(conn)
        _create_hypotheses_table(conn)
        _create_patterns_table(conn)

        assert {
            "findings",
            "test_history",
            "attack_surface",
            "defenses",
            "observations",
            "hypotheses",
            "patterns",
        } <= _sqlite_names(conn, "table")
        assert {
            "idx_findings_host",
            "idx_findings_type",
            "idx_history_host",
            "idx_obs_host",
            "idx_hyp_host",
            "idx_patterns_outcome",
        } <= _sqlite_names(conn, "index")
