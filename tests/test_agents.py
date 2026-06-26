"""Tests for the agent definitions."""

from __future__ import annotations

from pathlib import Path

import responses

from bugbounty_ctf.agents import (
    AgentContext,
    ExploitAgent,
    FuzzAgent,
    ReconAgent,
    ResearchAgent,
    create_agent,
)
from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.knowledge import KnowledgeBase


class TestAgentContext:
    def test_creates_context(self) -> None:
        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        assert ctx.scanner == scanner
        assert ctx.knowledge_base == kb
        assert ctx.target_url == "http://target/"
        assert ctx.tech_hints == []
        assert ctx.findings == []


class TestReconAgent:
    @responses.activate
    def test_run_maps_surface(self) -> None:
        html = """
        <html>
        <form action="/login" method="post"><input name="user"></form>
        <a href="/api">API</a>
        </html>
        """
        responses.add(responses.GET, "http://target/", body=html, status=200)

        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        agent = ReconAgent(ctx)
        result = agent.run()

        assert result.agent_name == "recon"
        assert "surface" in result.data
        assert len(result.data["surface"]["forms"]) == 1
        assert ctx.tech_hints is not None
        assert len(result.recommendations) > 0

    def test_build_prompt_includes_target(self) -> None:
        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        agent = ReconAgent(ctx)
        prompt = agent.build_prompt()
        assert "http://target" in prompt
        assert "reconnaissance" in prompt.lower()


class TestResearchAgent:
    def test_run_queries_knowledge_base(self, tmp_path: Path) -> None:
        refs_dir = Path(__file__).parent.parent / "references"
        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(refs_dir))
        kb.reindex()

        scanner = SecurityScanner("http://target/")
        ctx = AgentContext(
            scanner=scanner,
            knowledge_base=kb,
            target_url="http://target/",
            tech_hints=["nginx", "PHP"],
        )
        agent = ResearchAgent(ctx)
        result = agent.run()

        assert result.agent_name == "research"
        assert len(result.data["methodology"]) > 0
        assert len(result.recommendations) > 0

    def test_build_prompt_includes_tech_hints(self) -> None:
        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(
            scanner=scanner,
            knowledge_base=kb,
            target_url="http://target/",
            tech_hints=["Flask", "Jinja2"],
        )
        agent = ResearchAgent(ctx)
        prompt = agent.build_prompt()
        assert "Flask" in prompt
        assert "Jinja2" in prompt


class TestFuzzAgent:
    @responses.activate
    def test_run_tests_endpoints(self) -> None:
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

        scanner = SecurityScanner("http://target/", delay=0)
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        ctx.surface = {"links": ["http://target/search"], "forms": []}
        agent = FuzzAgent(ctx)
        result = agent.run()

        assert result.agent_name == "fuzz"
        assert len(result.findings) > 0


class TestExploitAgent:
    def test_run_identifies_chains(self) -> None:
        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        ctx.findings = [
            {"type": "sqli", "endpoint": "/login", "payload": "'", "indicators": ["sql_error"]},
            {"type": "ssrf", "endpoint": "/fetch", "payload": "http://x", "indicators": []},
        ]
        agent = ExploitAgent(ctx)
        result = agent.run()

        assert result.agent_name == "exploit"
        assert len(result.data["chains"]) >= 2
        chain_names = [c["name"] for c in result.data["chains"]]
        assert any("SQLi" in name for name in chain_names)
        assert any("SSRF" in name for name in chain_names)

    def test_build_prompt_includes_findings(self) -> None:
        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        ctx.findings = [{"type": "sqli", "endpoint": "/login", "payload": "'"}]
        agent = ExploitAgent(ctx)
        prompt = agent.build_prompt()
        assert "sqli" in prompt.lower()
        assert "/login" in prompt


class TestCreateAgent:
    def test_creates_recon_agent(self) -> None:
        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        agent = create_agent("recon", ctx)
        assert isinstance(agent, ReconAgent)

    def test_creates_all_agents(self) -> None:
        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        for name in ["recon", "research", "fuzz", "exploit"]:
            agent = create_agent(name, ctx)
            assert agent.name == name

    def test_unknown_agent_raises(self) -> None:
        import pytest

        scanner = SecurityScanner("http://target/")
        kb = KnowledgeBase()
        ctx = AgentContext(scanner=scanner, knowledge_base=kb, target_url="http://target/")
        with pytest.raises(ValueError, match="Unknown agent"):
            create_agent("nonexistent", ctx)
