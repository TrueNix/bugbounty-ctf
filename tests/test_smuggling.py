"""Tests for HTTP request smuggling module."""

from __future__ import annotations

from bugbounty_ctf.smuggling import SmugglingDetector, SmugglingResult


class TestSmugglingResult:
    def test_to_dict(self) -> None:
        result = SmugglingResult(
            vulnerable=True,
            technique="CL.TE",
            evidence="Timeout detected",
            timing_diff=10.0,
        )
        d = result.to_dict()
        assert d["vulnerable"] is True
        assert d["technique"] == "CL.TE"
        assert d["timing_diff"] == 10.0


class TestSmugglingDetector:
    def test_init(self) -> None:
        detector = SmugglingDetector("http://target/")
        assert detector.target_url == "http://target"

    def test_detect_returns_dict(self) -> None:
        detector = SmugglingDetector("http://nonexistent.invalid/")
        results = detector.detect()
        assert "vulnerable" in results
        assert "results" in results
        assert isinstance(results["results"], list)

    def test_exploit_clte_returns_dict(self) -> None:
        detector = SmugglingDetector("http://nonexistent.invalid/")
        result = detector.exploit_clte("/admin", smuggled_body="test=true")
        assert "success" in result

    def test_exploit_store_response_returns_dict(self) -> None:
        detector = SmugglingDetector("http://nonexistent.invalid/")
        result = detector.exploit_store_response("/api/secret")
        assert "success" in result
