"""Tests for the hypothesis-driven testing engine."""

from __future__ import annotations

from pathlib import Path

import responses

from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.hypothesis import Hypothesis, HypothesisEngine
from bugbounty_ctf.hypothesis import TestStep as TestStepData


class TestHypothesis:
    def test_confidence_update_for(self) -> None:
        h = Hypothesis(
            vuln_type="sqli",
            endpoint="/login",
            param="user",
            confidence=0.1,
            threshold=0.3,
        )
        test = TestStepData(payload="'", expect="sql_error", weight=0.3)
        test.evidence_for = True
        h.update_confidence(test)
        assert h.confidence == 0.4
        assert h.confirmed is True

    def test_confidence_update_against(self) -> None:
        h = Hypothesis(
            vuln_type="sqli",
            endpoint="/login",
            param="user",
            confidence=0.1,
            threshold=0.9,
        )
        test = TestStepData(payload="'", expect="sql_error", weight=0.3)
        test.evidence_against = True
        h.update_confidence(test)
        assert h.confidence < 0.1

    def test_rejection_at_zero(self) -> None:
        h = Hypothesis(
            vuln_type="sqli",
            endpoint="/login",
            param="user",
            confidence=0.05,
            threshold=0.9,
        )
        test = TestStepData(payload="'", weight=0.1)
        test.evidence_against = True
        h.update_confidence(test)
        assert h.rejected is True

    def test_to_dict(self) -> None:
        h = Hypothesis(
            vuln_type="sqli",
            endpoint="/login",
            param="user",
            confidence=0.5,
        )
        d = h.to_dict()
        assert d["vuln_type"] == "sqli"
        assert d["confidence"] == 0.5


class TestHypothesisEngine:
    @responses.activate
    def test_generate_hypotheses_for_form(self) -> None:
        responses.add(responses.GET, "http://target/", body="<html></html>", status=200)
        for _ in range(40):
            responses.add(responses.GET, "http://target/", body="<html></html>", status=200)

        scanner = SecurityScanner("http://target/", delay=0)
        engine = HypothesisEngine(scanner)
        hypotheses = engine.generate_hypotheses("/login", method="POST", data={"username": "test"})

        assert len(hypotheses) > 0
        vuln_types = {h.vuln_type for h in hypotheses}
        assert "sqli" in vuln_types
        assert "cmdi" in vuln_types
        assert "xss" in vuln_types

    @responses.activate
    def test_rejects_false_positive(self) -> None:
        responses.add(responses.GET, "http://target/", body="<html></html>", status=200)
        responses.add(
            responses.POST,
            "http://target/login",
            body="normal response",
            status=200,
        )
        for _ in range(40):
            responses.add(responses.GET, "http://target/", body="<html></html>", status=200)

        scanner = SecurityScanner("http://target/", delay=0)
        engine = HypothesisEngine(scanner)
        engine.generate_hypotheses("/login", method="POST", data={"username": "test"})
        results = engine.run()

        assert results["summary"]["confirmed_count"] == 0

    @responses.activate
    def test_confirms_real_sqli(self) -> None:
        responses.add(responses.GET, "http://target/", body="<html></html>", status=200)
        responses.add(
            responses.POST,
            "http://target/login",
            body="Login failed",
            status=200,
            match=[
                responses.matchers.urlencoded_params_matcher({"username": "baseline_test_value"})
            ],
        )
        responses.add(
            responses.POST,
            "http://target/login",
            body="SQL syntax error near 'OR 1=1",
            status=500,
            match=[responses.matchers.urlencoded_params_matcher({"username": "'"})],
        )
        for _ in range(40):
            responses.add(responses.GET, "http://target/", body="<html></html>", status=200)

        scanner = SecurityScanner("http://target/", delay=0)
        engine = HypothesisEngine(scanner)
        engine.generate_hypotheses("http://target/login", method="POST", data={"username": "test"})

        for h in engine.hypotheses:
            if h.vuln_type == "sqli":
                h.threshold = 0.2

        engine.run()

        confirmed = [h for h in engine.confirmed if h.vuln_type == "sqli"]
        assert len(confirmed) >= 1

    def test_ssrf_hypothesis_only_for_url_params(self) -> None:
        scanner = SecurityScanner("http://target/", delay=0)
        engine = HypothesisEngine(scanner)
        hypotheses = engine.generate_hypotheses("/fetch", method="POST", data={"url": "test"})
        ssrf_h = [h for h in hypotheses if h.vuln_type == "ssrf"]
        assert len(ssrf_h) >= 1

        engine2 = HypothesisEngine(scanner)
        hypotheses2 = engine2.generate_hypotheses("/fetch", method="POST", data={"name": "test"})
        ssrf_h2 = [h for h in hypotheses2 if h.vuln_type == "ssrf"]
        assert len(ssrf_h2) == 0

    def test_load_prior_isolates_same_host_different_ports(self, tmp_path: Path) -> None:
        # Given: a confirmed hypothesis was persisted for one host:port target.
        db_path = tmp_path / "scanner.db"
        scanner_a = SecurityScanner("http://10.1.2.3:8080", db=ScannerDB(str(db_path)))
        HypothesisEngine(scanner_a)._persist(
            Hypothesis(
                vuln_type="sqli",
                endpoint="/login",
                param="user",
                confidence=0.9,
                confirmed=True,
            )
        )

        # When: another scanner targets the same host on a different port.
        scanner_b = SecurityScanner("http://10.1.2.3:9090", db=ScannerDB(str(db_path)))
        prior = HypothesisEngine(scanner_b).load_prior(status="confirmed")

        # Then: host-only state does not bleed across target identities.
        assert scanner_a.host == scanner_b.host
        assert scanner_a.target_identity != scanner_b.target_identity
        assert prior == []

    def test_load_prior_reloads_exact_target_identity(self, tmp_path: Path) -> None:
        # Given: a confirmed hypothesis was persisted for an IP:port plus Host header context.
        db_path = tmp_path / "scanner.db"
        scanner_a = SecurityScanner(
            "http://10.1.2.3:8080",
            db=ScannerDB(str(db_path)),
            headers={"Host": "App.One:8080"},
        )
        HypothesisEngine(scanner_a)._persist(
            Hypothesis(
                vuln_type="xss",
                endpoint="/profile",
                param="name",
                confidence=0.95,
                confirmed=True,
            )
        )

        # When: a fresh scanner uses the same normalized target identity.
        scanner_b = SecurityScanner(
            "http://10.1.2.3:8080",
            db=ScannerDB(str(db_path)),
            headers={"host": "app.one:8080"},
        )
        prior = HypothesisEngine(scanner_b).load_prior(status="confirmed")

        # Then: the exact target identity is the persisted reload key.
        assert scanner_b.target_identity == scanner_a.target_identity
        assert [p["vuln_type"] for p in prior] == ["xss"]
        assert scanner_b.db.query_hypotheses(scanner_b.target_identity, status="confirmed") == prior
