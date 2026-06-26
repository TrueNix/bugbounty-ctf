"""Tests for the multi-agent orchestrator."""

from __future__ import annotations

from pathlib import Path

import responses

from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.orchestrator import Orchestrator, PhaseResult


class TestOrchestratorInit:
    def test_creates_scanner(self) -> None:
        orch = Orchestrator("http://target/")
        assert orch.scanner.base_url == "http://target"
        assert orch.report.target == "http://target"

    def test_report_starts_empty(self) -> None:
        orch = Orchestrator("http://target/")
        assert orch.report.phases == []
        assert orch.report.total_findings == 0


class TestReconPhase:
    @responses.activate
    def test_recon_maps_surface(self) -> None:
        html = """
        <html>
        <form action="/login" method="post"><input name="user"></form>
        <a href="/api/v1/health">Health</a>
        </html>
        """
        responses.add(responses.GET, "http://target/", body=html, status=200)

        orch = Orchestrator("http://target/")
        result = orch.run_phase_recon()

        assert result.phase == "recon"
        assert "forms" in result.surface
        assert len(result.surface["forms"]) == 1
        assert result.surface["forms"][0]["action"] == "http://target/login"
        assert "http://target/api/v1/health" in result.surface["links"]
        assert len(result.recommendations) > 0


class TestResearchPhase:
    def test_research_queries_knowledge_base(self, tmp_path: Path) -> None:
        from bugbounty_ctf.knowledge import KnowledgeBase

        refs_dir = Path(__file__).parent.parent / "references"
        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(refs_dir))
        kb.reindex()

        scanner = SecurityScanner("http://target/")
        orch = Orchestrator("http://target/", scanner=scanner, knowledge_base=kb)
        result = orch.run_phase_research(["nginx", "PHP"])

        assert result.phase == "research"
        assert len(result.methodology) > 0
        assert len(result.recommendations) > 0


class TestFuzzPhase:
    @responses.activate
    def test_fuzz_tests_endpoints(self) -> None:
        responses.add(responses.GET, "http://target/", body="<html>home</html>", status=200)
        responses.add(
            responses.GET,
            "http://target/search",
            body="normal",
            status=200,
            match=[responses.matchers.query_param_matcher({"q": "test"})],
        )
        responses.add(
            responses.GET,
            "http://target/search",
            body="SQL syntax error",
            status=500,
            match=[responses.matchers.query_param_matcher({"q": "'"})],
        )
        for _ in range(30):
            responses.add(responses.GET, "http://target/", body="<html>home</html>", status=200)

        orch = Orchestrator("http://target/", delay=0)
        orch.run_phase_recon()
        result = orch.run_phase_fuzz(["http://target/search"])

        assert result.phase == "fuzz"
        assert len(result.findings) > 0


class TestExploitPhase:
    def test_exploit_identifies_chains(self) -> None:
        orch = Orchestrator("http://target/")
        findings = [
            {"type": "sqli", "endpoint": "/login", "payload": "'", "indicators": ["sql_error"]},
            {
                "type": "ssrf",
                "endpoint": "/fetch",
                "payload": "http://169.254.169.254",
                "indicators": [],
            },
        ]
        result = orch.run_phase_exploit(findings)

        assert result.phase == "exploit"
        assert len(result.findings) > 0
        chain_names = [c["name"] for c in result.findings]
        assert any("SQLi" in name for name in chain_names)
        assert any("SSRF" in name for name in chain_names)

    def test_exploit_no_findings(self) -> None:
        orch = Orchestrator("http://target/")
        result = orch.run_phase_exploit([])
        assert result.phase == "exploit"
        assert result.findings == []


class TestFullRun:
    @responses.activate
    def test_full_run_produces_report(self) -> None:
        responses.add(responses.GET, "http://target/", body="<html>home</html>", status=200)

        orch = Orchestrator("http://target/")
        report = orch.run()

        assert report.target == "http://target"
        assert len(report.phases) == 4
        assert report.phases[0].phase == "recon"
        assert report.phases[1].phase == "research"
        assert report.phases[2].phase == "fuzz"
        assert report.phases[3].phase == "exploit"


class TestReportSerialization:
    def test_report_to_json(self) -> None:
        orch = Orchestrator("http://target/")
        orch.report.phases.append(PhaseResult(phase="test"))
        json_str = orch.report.to_json()
        assert '"target": "http://target"' in json_str
        assert '"phase": "test"' in json_str
