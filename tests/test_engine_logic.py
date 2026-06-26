"""Tests for engine logic fixes: baseline content comparison, IDOR similarity, scan_endpoint."""

from __future__ import annotations

from pathlib import Path

import responses

from bugbounty_ctf.engine import (
    ResponseDiff,
    ScannerDB,
    SecurityScanner,
    _similarity_ratio,
    _strip_noise,
)


class TestBaselineContentComparison:
    """Verify _check_content only flags patterns that are NEW (not in baseline)."""

    @responses.activate
    def test_pattern_in_baseline_is_not_flagged(self) -> None:
        """If baseline already contains 'uid=1000', a test with the same should NOT flag command_output."""
        class FakeResp:
            def __init__(self, text: str, status: int = 200) -> None:
                self.text = text
                self.status_code = status
                self.headers: dict[str, str] = {}
                self.response_time = 0.1

        baseline = FakeResp("uid=1000(root) some page content")
        test = FakeResp("uid=1000(root) some other content")
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "command_output" not in analysis.indicators

    @responses.activate
    def test_pattern_new_in_test_is_flagged(self) -> None:
        class FakeResp:
            def __init__(self, text: str, status: int = 200) -> None:
                self.text = text
                self.status_code = status
                self.headers: dict[str, str] = {}
                self.response_time = 0.1

        baseline = FakeResp("normal page content")
        test = FakeResp("uid=1000(root) gid=1000(root)")
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "command_output" in analysis.indicators


class TestStripNoise:
    def test_strips_csrf_token(self) -> None:
        text = '<input name="csrf_token" value="abc123">Hello</input>'
        cleaned = _strip_noise(text)
        assert "abc123" not in cleaned
        assert "Hello" in cleaned

    def test_strips_viewstate(self) -> None:
        text = '<input name="__VIEWSTATE" value="longencodedstring">Content'
        cleaned = _strip_noise(text)
        assert "longencodedstring" not in cleaned
        assert "Content" in cleaned

    def test_preserves_normal_content(self) -> None:
        text = "Just some normal page content"
        assert _strip_noise(text) == text


class TestSimilarityRatio:
    def test_identical_texts_have_ratio_1(self) -> None:
        assert _similarity_ratio("hello world", "hello world") == 1.0

    def test_completely_different_texts_have_low_ratio(self) -> None:
        ratio = _similarity_ratio("aaaaaaa", "zzzzzzz")
        assert ratio < 0.2

    def test_ignores_csrf_noise(self) -> None:
        text_a = '<input name="csrf_token" value="abc">Hello admin'
        text_b = '<input name="csrf_token" value="xyz">Hello admin'
        ratio = _similarity_ratio(text_a, text_b)
        assert ratio > 0.9


class TestScannerDB:
    def test_save_and_query_finding(self, tmp_path: Path) -> None:
        db_path = str(tmp_path / "test.db")
        db = ScannerDB(db_path=db_path)
        db.save_finding(
            target_host="target.com",
            endpoint="/login",
            vuln_type="sqli",
            method="POST",
            payload="' OR 1=1--",
            confidence=0.9,
            indicators=["sql_error"],
            details=["Status: 200 → 500"],
        )
        results = db.query_findings("vuln_type = ?", ("sqli",))
        assert len(results) == 1
        assert results[0]["endpoint"] == "/login"
        assert results[0]["vuln_type"] == "sqli"
        db.close()

    def test_query_empty_db_returns_empty(self, tmp_path: Path) -> None:
        db_path = str(tmp_path / "empty.db")
        db = ScannerDB(db_path=db_path)
        assert db.query_findings() == []
        db.close()


class TestPerTargetStateFile:
    def test_different_targets_get_different_state_files(self) -> None:
        scanner_a = SecurityScanner("http://target-a.com/")
        scanner_b = SecurityScanner("http://target-b.com/")
        assert scanner_a.state_file != scanner_b.state_file
        assert "target-a.com" in scanner_a.state_file
        assert "target-b.com" in scanner_b.state_file


class TestRequestPacing:
    @responses.activate
    def test_delay_is_applied(self) -> None:
        import time

        responses.add(responses.GET, "http://target/test", json={"ok": True}, status=200)
        scanner = SecurityScanner("http://target/", delay=0.1)
        start = time.time()
        scanner._make_request("GET", "http://target/test")
        elapsed = time.time() - start
        assert elapsed >= 0.08  # Allow small jitter


class TestRetryOnTransientFailure:
    def test_retries_on_connection_error(self) -> None:
        from unittest.mock import MagicMock, patch

        from requests.exceptions import ConnectionError as ReqConnError

        scanner = SecurityScanner("http://target/", delay=0)
        call_count = [0]

        good_response = MagicMock()
        good_response.status_code = 200
        good_response.text = "ok"
        good_response.headers = {}

        def flaky_request(*args: object, **kwargs: object) -> object:
            call_count[0] += 1
            if call_count[0] == 1:
                raise ReqConnError("transient")
            good_response.response_time = 0.01
            return good_response

        with patch.object(scanner.session, "request", side_effect=flaky_request):
            r = scanner._make_request("GET", "http://target/test")
        assert call_count[0] == 2
        assert r.status_code == 200
