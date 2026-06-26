"""Tests for the observation schema."""

from __future__ import annotations

from bugbounty_ctf.observations import Observation, ObservationStore, recommend_next_test


class TestObservation:
    def test_creation(self) -> None:
        obs = Observation(
            endpoint="/login",
            method="POST",
            param="username",
            payload="' OR 1=1--",
            status_code=302,
            response_length=1200,
            indicators=["auth_bypass"],
            evidence="Redirect to /dashboard",
            confidence=0.8,
            vuln_type="sqli",
        )
        assert obs.endpoint == "/login"
        assert obs.is_confirmed() is True
        assert obs.is_interesting() is True

    def test_not_confirmed_low_confidence(self) -> None:
        obs = Observation(endpoint="/x", confidence=0.2)
        assert obs.is_confirmed() is False
        assert obs.is_interesting() is False

    def test_to_dict(self) -> None:
        obs = Observation(endpoint="/x", confidence=0.5, vuln_type="sqli")
        d = obs.to_dict()
        assert d["endpoint"] == "/x"
        assert d["confidence"] == 0.5
        assert d["vuln_type"] == "sqli"


class TestObservationStore:
    def test_add_and_query(self) -> None:
        store = ObservationStore()
        store.add_finding("/login", "sqli", "' OR 1=1--", confidence=0.8)
        store.add_finding("/search", "xss", "<script>", confidence=0.5)
        store.add_finding("/api", "idor", "2", confidence=0.1)

        all_obs = store.query()
        assert len(all_obs) == 3

        confirmed = store.query(confirmed_only=True)
        assert len(confirmed) == 1
        assert confirmed[0].vuln_type == "sqli"

    def test_query_by_vuln_type(self) -> None:
        store = ObservationStore()
        store.add_finding("/login", "sqli", confidence=0.8)
        store.add_finding("/search", "xss", confidence=0.5)
        store.add_finding("/admin", "sqli", confidence=0.6)

        sqli = store.query(vuln_type="sqli")
        assert len(sqli) == 2

    def test_query_by_endpoint(self) -> None:
        store = ObservationStore()
        store.add_finding("/login", "sqli", confidence=0.8)
        store.add_finding("/search", "xss", confidence=0.5)

        results = store.query(endpoint="/login")
        assert len(results) == 1

    def test_min_confidence_filter(self) -> None:
        store = ObservationStore()
        store.add_finding("/a", "sqli", confidence=0.1)
        store.add_finding("/b", "sqli", confidence=0.5)
        store.add_finding("/c", "sqli", confidence=0.9)

        results = store.query(min_confidence=0.5)
        assert len(results) == 2

    def test_summary(self) -> None:
        store = ObservationStore()
        store.add_finding("/login", "sqli", confidence=0.8)
        store.add_finding("/search", "xss", confidence=0.5)

        summary = store.summary()
        assert summary["total"] == 2
        assert summary["confirmed"] == 1
        assert "sqli" in summary["by_vuln_type"]

    def test_by_vuln_type(self) -> None:
        store = ObservationStore()
        store.add_finding("/a", "sqli", confidence=0.8)
        store.add_finding("/b", "xss", confidence=0.5)
        store.add_finding("/c", "sqli", confidence=0.6)

        groups = store.by_vuln_type()
        assert len(groups["sqli"]) == 2
        assert len(groups["xss"]) == 1

    def test_from_findings(self) -> None:
        store = ObservationStore()
        findings = [
            {"type": "sqli", "endpoint": "/login", "payload": "'", "indicators": ["sql_error"]},
            {"type": "xss", "endpoint": "/search", "payload": "<script>", "indicators": []},
        ]
        store.from_findings(findings)
        assert len(store.observations) == 2


class TestRecommendNextTest:
    def test_high_confidence_sqli(self) -> None:
        rec = recommend_next_test("sqli", 0.9)
        assert "UNION" in rec

    def test_high_confidence_ssrf(self) -> None:
        rec = recommend_next_test("ssrf", 0.9)
        assert "metadata" in rec.lower()

    def test_low_confidence(self) -> None:
        rec = recommend_next_test("sqli", 0.1)
        assert "more" in rec.lower()

    def test_medium_confidence(self) -> None:
        rec = recommend_next_test("sqli", 0.5)
        assert "confirmation" in rec.lower()
