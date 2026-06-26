"""Tests for ResponseDiff — the core response comparison engine."""

from __future__ import annotations

from bugbounty_ctf.engine import ResponseDiff


class _FakeResp:
    """Minimal fake requests.Response for unit tests."""

    def __init__(
        self,
        status: int = 200,
        text: str = "hello",
        headers: dict[str, str] | None = None,
        response_time: float = 0.1,
    ) -> None:
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.response_time = response_time


class TestResponseDiffStatus:
    def test_status_change_is_interesting(self) -> None:
        baseline = _FakeResp(status=200)
        test = _FakeResp(status=500)
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert analysis.status_changed is True
        assert analysis.interesting is True
        assert "status_code_change" in analysis.indicators

    def test_same_status_not_interesting_from_status(self) -> None:
        baseline = _FakeResp(status=200, text="a")
        test = _FakeResp(status=200, text="b")
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        # content differs but no vuln indicators
        assert "status_code_change" not in analysis.indicators


class TestResponseDiffLength:
    def test_significant_length_change_is_interesting(self) -> None:
        baseline = _FakeResp(text="x" * 100)
        test = _FakeResp(text="x" * 200)  # 100% increase > 5%
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert analysis.interesting is True
        assert "length_change" in analysis.indicators

    def test_small_length_change_not_flagged(self) -> None:
        baseline = _FakeResp(text="x" * 100)
        test = _FakeResp(text="x" * 103)  # 3% < 5%
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "length_change" not in analysis.indicators


class TestResponseDiffTiming:
    def test_timing_delay_is_interesting(self) -> None:
        baseline = _FakeResp(response_time=0.1)
        test = _FakeResp(response_time=3.0)  # 30x slower, >1s
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert analysis.interesting is True
        assert "timing_delay" in analysis.indicators

    def test_small_timing_not_flagged(self) -> None:
        baseline = _FakeResp(response_time=0.5)
        test = _FakeResp(response_time=0.6)
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "timing_delay" not in analysis.indicators


class TestResponseDiffContentPatterns:
    def test_sql_error_detected(self) -> None:
        baseline = _FakeResp(text="normal page")
        test = _FakeResp(text="Error: You have an error in your SQL syntax")
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "sql_error" in analysis.indicators
        assert analysis.interesting is True

    def test_command_output_detected(self) -> None:
        baseline = _FakeResp(text="normal")
        test = _FakeResp(text="uid=1000 gid=1000")
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "command_output" in analysis.indicators

    def test_flag_found_detected(self) -> None:
        baseline = _FakeResp(text="normal")
        test = _FakeResp(text="Congratulations! flag{test_flag_123}")
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "flag_found" in analysis.indicators

    def test_ssti_evaluated_detected(self) -> None:
        baseline = _FakeResp(text="normal")
        test = _FakeResp(text="Result: 49")
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "ssti_evaluated" in analysis.indicators


class TestResponseDiffRedirects:
    def test_redirect_detected(self) -> None:
        baseline = _FakeResp(status=200)
        test = _FakeResp(status=302, headers={"Location": "/admin"})
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "redirect" in analysis.indicators
        assert analysis.interesting is True


class TestResponseDiffHeaders:
    def test_cookie_set_is_interesting(self) -> None:
        baseline = _FakeResp(headers={})
        test = _FakeResp(headers={"set-cookie": "session=abc123"})
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "cookie_set" in analysis.indicators
        assert analysis.interesting is True


class TestResponseDiffWAF:
    def test_waf_response_detected(self) -> None:
        baseline = _FakeResp(text="normal page")
        test = _FakeResp(text="Request blocked by Cloudflare")
        diff = ResponseDiff(baseline, test)
        analysis = diff.analyze()
        assert "defense_triggered" in analysis.indicators
