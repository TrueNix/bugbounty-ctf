"""Tests for the Hermes SkillOrchestrator and its sub-agent spawning."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from bugbounty_ctf import skill_runner
from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.skill_runner import PhaseGuidance, SkillOrchestrator


class _FakeKB:
    def __init__(self) -> None:
        self.lessons: list[tuple[str, str]] = []

    def search(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        return []

    def suggest_methodology(self, tech: list[str]) -> list[dict[str, Any]]:
        return []

    def add_lesson(
        self, title: str, body: str, *, tags: str = "", host: str = "", key: str = ""
    ) -> bool:
        self.lessons.append((title, body))
        return True


@pytest.fixture
def runner() -> SkillOrchestrator:
    scanner = SecurityScanner("http://target.test/", db=ScannerDB(":memory:"))
    return SkillOrchestrator("http://target.test/", scanner=scanner, knowledge_base=_FakeKB())


class TestGuidance:
    def test_each_phase_returns_its_guidance(self, runner: SkillOrchestrator) -> None:
        assert runner.get_recon_guidance().phase == "recon"
        assert runner.get_research_guidance().phase == "research"
        assert runner.get_fuzz_guidance().phase == "fuzz"
        assert runner.get_exploit_guidance().phase == "exploit"

    def test_run_all_phases_covers_four(self, runner: SkillOrchestrator) -> None:
        phases = runner.run_all_phases()
        assert [g.phase for g in phases] == ["recon", "research", "fuzz", "exploit"]

    def test_collect_results_shape(self, runner: SkillOrchestrator) -> None:
        results = runner.collect_results()
        assert results["target"] == "http://target.test"
        assert "findings" in results
        assert "attack_surface" in results


class TestPromptBuilding:
    def test_prompt_includes_phase_and_tools(self) -> None:
        guidance = PhaseGuidance(
            phase="fuzz",
            discovered={"forms": []},
            available_tools=["scanner.scan_endpoint(...)"],
            rag_context="some methodology",
            scanner_state="findings: 0",
        )
        prompt = SkillOrchestrator._build_agent_prompt(guidance)
        assert "fuzz phase" in prompt
        assert "scanner.scan_endpoint(...)" in prompt
        assert "some methodology" in prompt

    def test_prompt_includes_shared_state_bootstrap(self) -> None:
        guidance = PhaseGuidance(
            phase="recon",
            target_url="http://target.test",
            state_file="/tmp/state.json",
            db_path="/tmp/findings.db",
        )
        prompt = SkillOrchestrator._build_agent_prompt(guidance)
        # The sub-agent must be told to share the orchestrator's persistence.
        assert "Bootstrap" in prompt
        assert "http://target.test" in prompt
        assert "/tmp/state.json" in prompt
        assert "/tmp/findings.db" in prompt

    def test_prompt_omits_bootstrap_without_target(self) -> None:
        prompt = SkillOrchestrator._build_agent_prompt(PhaseGuidance(phase="recon"))
        assert "Bootstrap" not in prompt


class TestFeedForward:
    """The sub-agent workflow must build each phase from current state and
    aggregate findings sub-agents persist (the old code snapshotted all four
    phases upfront and never reloaded)."""

    def _orchestrator(self, tmp_path: Path) -> SkillOrchestrator:
        scanner = SecurityScanner(
            "http://target.test/",
            state_file=str(tmp_path / "state.json"),
            db=ScannerDB(":memory:"),
        )
        return SkillOrchestrator("http://target.test/", scanner=scanner, knowledge_base=_FakeKB())

    def test_guidance_is_built_lazily_and_findings_accumulate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        orch = self._orchestrator(tmp_path)
        seen_prev_counts: list[int] = []

        def fake_spawn(guidance: PhaseGuidance, *, timeout: int = 120) -> str:
            # Record what THIS phase saw, proving guidance is built lazily.
            seen_prev_counts.append(len(guidance.previous_findings))
            # Simulate a sub-agent persisting one finding to the shared state.
            new_finding = {"type": f"vuln_{guidance.phase}", "endpoint": "/x"}
            state = {
                "base_url": guidance.target_url,
                "findings": [*orch.scanner.findings, new_finding],
                "test_history": [],
                "attack_surface": {},
                "defenses_detected": [],
            }
            Path(guidance.state_file).write_text(json.dumps(state))
            return "ok"

        monkeypatch.setattr(orch, "spawn_agent", fake_spawn)
        final = orch.run_with_agents(verify=False)

        # One finding persisted per phase, reloaded and carried forward.
        assert final["total_findings"] == len(orch.PHASES)
        # fuzz/exploit guidance saw findings the earlier agents persisted.
        assert seen_prev_counts[-1] > 0
        assert seen_prev_counts == sorted(seen_prev_counts)


class TestSecondBrain:
    def test_recon_guidance_recalls_prior_findings(self, runner: SkillOrchestrator) -> None:
        # Seed the DB as if a past run found something on this host.
        runner.scanner.db.save_finding(
            runner.scanner.host, "/login", "sqli", payload="'", confidence=0.9
        )
        guidance = runner.get_recon_guidance()
        assert any(m["vuln_type"] == "sqli" for m in guidance.prior_memory)

    def test_prior_memory_rendered_in_prompt(self, runner: SkillOrchestrator) -> None:
        runner.scanner.db.save_finding(runner.scanner.host, "/login", "sqli", payload="'")
        prompt = SkillOrchestrator._build_agent_prompt(runner.get_recon_guidance())
        assert "Prior memory" in prompt
        assert "sqli @ /login" in prompt

    def test_writeback_creates_lessons(self, runner: SkillOrchestrator) -> None:
        n = runner._writeback_lessons(
            [{"type": "sqli", "endpoint": "/login", "payload": "'", "details": ["SQL error"]}]
        )
        assert n == 1
        kb = runner.kb
        assert isinstance(kb, _FakeKB)
        assert any("sqli on target.test/login" in title for title, _ in kb.lessons)


class TestStructuredOutput:
    def test_parse_findings_extracts_array(self) -> None:
        resp = (
            "I tested the login.\n"
            '<FINDINGS>[{"type":"sqli","endpoint":"/login","payload":"\'"}]</FINDINGS>\n'
            "Done."
        )
        findings = SkillOrchestrator._parse_findings(resp)
        assert len(findings) == 1
        assert findings[0]["type"] == "sqli"

    def test_parse_findings_handles_json_fence(self) -> None:
        resp = '<FINDINGS>\n```json\n[{"type":"xss","endpoint":"/q"}]\n```\n</FINDINGS>'
        findings = SkillOrchestrator._parse_findings(resp)
        assert findings[0]["type"] == "xss"

    def test_parse_findings_tolerates_garbage(self) -> None:
        assert SkillOrchestrator._parse_findings("no block here") == []
        assert SkillOrchestrator._parse_findings("<FINDINGS>not json</FINDINGS>") == []

    def test_merge_dedups(self, runner: SkillOrchestrator) -> None:
        f = {"type": "sqli", "endpoint": "/login", "payload": "'", "evidence": "err"}
        assert runner._merge_agent_findings([f]) == 1
        # Same finding again → not re-added.
        assert runner._merge_agent_findings([f]) == 0
        assert len(runner.scanner.findings) == 1

    def test_prompt_requires_findings_block(self) -> None:
        prompt = SkillOrchestrator._build_agent_prompt(PhaseGuidance(phase="fuzz"))
        assert "<FINDINGS>" in prompt
        assert "Required output" in prompt


class TestVerification:
    def test_majority_refute_marks_refuted(
        self, runner: SkillOrchestrator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = {"n": 0}

        def fake_run(prompt: str, *, timeout: int, label: str = "agent") -> str:
            calls["n"] += 1
            refuted = "true" if calls["n"] <= 2 else "false"  # 2 of 3 refute
            return f'<VERDICT>{{"refuted": {refuted}, "reason": "x"}}</VERDICT>'

        monkeypatch.setattr(runner, "_run_hermes", fake_run)
        result = runner.verify_finding({"type": "sqli", "endpoint": "/x"}, votes=3)
        assert result["refuted"] is True
        assert len(result["votes"]) == 3

    def test_minority_refute_keeps_finding(
        self, runner: SkillOrchestrator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = {"n": 0}

        def fake_run(prompt: str, *, timeout: int, label: str = "agent") -> str:
            calls["n"] += 1
            refuted = "true" if calls["n"] == 1 else "false"  # only 1 of 3
            return f'<VERDICT>{{"refuted": {refuted}}}</VERDICT>'

        monkeypatch.setattr(runner, "_run_hermes", fake_run)
        result = runner.verify_finding({"type": "sqli", "endpoint": "/x"}, votes=3)
        assert result["refuted"] is False

    def test_run_with_agents_splits_confirmed_and_refuted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scanner = SecurityScanner(
            "http://target.test/",
            state_file=str(tmp_path / "s.json"),
            db=ScannerDB(":memory:"),
        )
        orch = SkillOrchestrator("http://target.test/", scanner=scanner, knowledge_base=_FakeKB())

        def fake_run(prompt: str, *, timeout: int, label: str = "agent") -> str:
            if "REFUTE" in prompt:
                return '<VERDICT>{"refuted": false, "reason": "reproduced"}</VERDICT>'
            return (
                '<FINDINGS>[{"type":"sqli","endpoint":"/login","payload":"\'",'
                '"evidence":"SQL error","confidence":"high"}]</FINDINGS>'
            )

        monkeypatch.setattr(orch, "_run_hermes", fake_run)
        final = orch.run_with_agents(verify=True, verify_votes=3)
        assert len(final["confirmed_findings"]) >= 1
        assert final["refuted_findings"] == []


class TestSpawnAgent:
    def test_success_returns_stdout(
        self, runner: SkillOrchestrator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*args: Any, **kwargs: Any) -> Any:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="agent output\n", stderr=""
            )

        monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)
        guidance = runner.get_recon_guidance()
        assert runner.spawn_agent(guidance) == "agent output"

    def test_nonzero_exit_surfaces_stderr(
        self, runner: SkillOrchestrator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*args: Any, **kwargs: Any) -> Any:
            return subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="boom")

        monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)
        out = runner.spawn_agent(runner.get_recon_guidance())
        assert out.startswith("[HERMES ERROR rc=2]")
        assert "boom" in out

    def test_missing_binary_raises(
        self, runner: SkillOrchestrator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*args: Any, **kwargs: Any) -> Any:
            raise FileNotFoundError("hermes")

        monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)
        with pytest.raises(SkillOrchestrator.HermesNotFoundError):
            runner.spawn_agent(runner.get_recon_guidance())

    def test_timeout_returns_marker(
        self, runner: SkillOrchestrator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*args: Any, **kwargs: Any) -> Any:
            raise subprocess.TimeoutExpired(cmd="hermes", timeout=1)

        monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)
        out = runner.spawn_agent(runner.get_recon_guidance(), timeout=1)
        assert "TIMEOUT" in out


class TestRunWithAgents:
    def test_missing_binary_aborts_cleanly(
        self, runner: SkillOrchestrator, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run(*args: Any, **kwargs: Any) -> Any:
            raise FileNotFoundError("hermes")

        monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)
        result = runner.run_with_agents()
        assert "agent_error" in result


class TestSaveResults:
    def test_save_results_to_explicit_path(self, runner: SkillOrchestrator, tmp_path: Path) -> None:
        out = tmp_path / "sub" / "results.json"
        path = runner.save_results(str(out))
        assert Path(path).exists()
