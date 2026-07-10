from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from bugbounty_ctf import skill_runner
from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.skill_runner import SkillOrchestrator


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


def _runner(tmp_path: Path) -> SkillOrchestrator:
    scanner = SecurityScanner(
        "http://target.test/",
        state_file=str(tmp_path / "state.json"),
        db=ScannerDB(":memory:"),
        headers={"Authorization": "Bearer scanner-secret"},
    )
    scanner.session.cookies.set("sessionid", "cookie-secret")
    return SkillOrchestrator("http://target.test/", scanner=scanner, knowledge_base=_FakeKB())


def _runner_with_real_kb(tmp_path: Path) -> SkillOrchestrator:
    from bugbounty_ctf.knowledge import KnowledgeBase

    refs = tmp_path / "refs"
    refs.mkdir()
    scanner = SecurityScanner(
        "http://target.test/",
        state_file=str(tmp_path / "state.json"),
        db=ScannerDB(":memory:"),
    )
    kb = KnowledgeBase(db_path=str(tmp_path / "kb.db"), references_dir=str(refs))
    return SkillOrchestrator("http://target.test/", scanner=scanner, knowledge_base=kb)


def _forbid_late_run_with_agents_work(
    runner: SkillOrchestrator, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_verify(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        pytest.fail("verification ran after an agent execution error")

    def fail_lessons(findings: list[dict[str, Any]]) -> int:
        pytest.fail(f"lessons were written after an agent execution error: {findings!r}")

    def fail_pattern(findings: list[dict[str, Any]]) -> str | None:
        pytest.fail(f"patterns were captured after an agent execution error: {findings!r}")

    def fail_feedback(findings: list[dict[str, Any]], *, now: str) -> dict[str, str]:
        pytest.fail(f"pattern feedback was scored after an agent execution error: {findings!r}")

    monkeypatch.setattr(runner, "verify_findings", fail_verify)
    monkeypatch.setattr(runner, "_writeback_lessons", fail_lessons)
    monkeypatch.setattr(runner, "_writeback_pattern", fail_pattern)
    monkeypatch.setattr(runner, "_score_pattern_feedback", fail_feedback)
    monkeypatch.setattr(runner, "save_results", lambda *args, **kwargs: pytest.fail("saved"))


def test_run_hermes_timeout_raises_structured_error_without_secret_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a scanner context with secrets and a prompt containing target-derived text.
    runner = _runner(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert "prompt-secret" in cmd[2]
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=7)

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: Hermes times out.
    with pytest.raises(Exception) as exc_info:
        runner._run_hermes("prompt-secret", timeout=7, label="research")

    # Then: the error is structured and excludes prompt/scanner-context secrets.
    assert isinstance(exc_info.value, SkillOrchestrator.HermesExecutionError)
    error = exc_info.value.to_dict()
    encoded = json.dumps(error, sort_keys=True)
    assert error["type"] == "timeout"
    assert error["label"] == "research"
    assert error["timeout"] == 7
    assert error["returncode"] is None
    assert "prompt-secret" not in encoded
    assert "scanner-secret" not in encoded
    assert "cookie-secret" not in encoded


def test_run_hermes_nonzero_raises_structured_error_with_bounded_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: Hermes exits non-zero and stderr repeats scanner-context secrets.
    runner = _runner(tmp_path)
    stderr = f"bad rc with Bearer scanner-secret and cookie-secret {'x' * 800}"

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=42, stdout="", stderr=stderr)

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: the subprocess exits non-zero.
    with pytest.raises(Exception) as exc_info:
        runner._run_hermes("prompt-secret", timeout=9, label="fuzz")

    # Then: rc/label/stderr are present, bounded, and scrubbed.
    assert isinstance(exc_info.value, SkillOrchestrator.HermesExecutionError)
    error = exc_info.value.to_dict()
    encoded = json.dumps(error, sort_keys=True)
    assert error["type"] == "nonzero_exit"
    assert error["label"] == "fuzz"
    assert error["returncode"] == 42
    assert error["timeout"] is None
    assert isinstance(error["stderr"], str)
    assert len(error["stderr"]) <= 500
    assert "prompt-secret" not in encoded
    assert "scanner-secret" not in encoded
    assert "cookie-secret" not in encoded


def test_run_hermes_nonzero_omits_stderr_echoing_prompt_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: stderr contains text that originated only in the prompt, not scanner headers.
    runner = _runner(tmp_path)
    prompt_secret = "prompt-only-secret-2a29cde9"
    stderr = f"diagnostic before {prompt_secret} diagnostic after"

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr=stderr)

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: Hermes exits non-zero.
    with pytest.raises(Exception) as exc_info:
        runner._run_hermes(f"investigate {prompt_secret}", timeout=9, label="fuzz")

    # Then: unsafe stderr is omitted rather than leaking prompt-derived text.
    assert isinstance(exc_info.value, SkillOrchestrator.HermesExecutionError)
    error = exc_info.value.to_dict()
    encoded = json.dumps(error, sort_keys=True)
    assert error["type"] == "nonzero_exit"
    assert error["label"] == "fuzz"
    assert error["returncode"] == 2
    assert error["stderr"] == ""
    assert prompt_secret not in encoded


def test_run_with_agents_aborts_timeout_phase_without_late_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: recon succeeds, then the research phase times out.
    runner = _runner(tmp_path)
    _forbid_late_run_with_agents_work(runner, monkeypatch)
    calls: list[str] = []

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append("call")
        if len(calls) == 1:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout="recon-ok\n", stderr=""
            )
        raise subprocess.TimeoutExpired(cmd="hermes", timeout=3)

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: the headless workflow runs.
    result = runner.run_with_agents(timeout_per_phase=3)

    # Then: it stops at the failed phase and reports only completed responses.
    assert len(calls) == 2
    assert result["agent_responses"] == {"recon": "recon-ok"}
    assert result["completed_phases"] == ["recon"]
    assert result["agent_error"]["type"] == "timeout"
    assert result["agent_error"]["label"] == "research"
    assert result["agent_error"]["timeout"] == 3
    assert "verification" not in result
    assert "lessons_written" not in result
    assert "pattern_captured" not in result
    assert "pattern_feedback" not in result


def test_run_with_agents_aborts_nonzero_phase_without_confirming_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: the first phase exits non-zero.
    runner = _runner(tmp_path)
    _forbid_late_run_with_agents_work(runner, monkeypatch)
    calls: list[str] = []

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append("call")
        return subprocess.CompletedProcess(args=[], returncode=2, stdout="", stderr="phase failed")

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: the headless workflow runs.
    result = runner.run_with_agents(timeout_per_phase=5)

    # Then: no phase is presented as successful or confirmed.
    assert len(calls) == 1
    assert result["agent_responses"] == {}
    assert result["completed_phases"] == []
    assert result["agent_error"]["type"] == "nonzero_exit"
    assert result["agent_error"]["label"] == "recon"
    assert result["agent_error"]["returncode"] == 2
    assert "confirmed_findings" not in result


def test_fan_out_timeout_track_reports_agent_error_without_dead_end_poisoning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bugbounty_ctf.recon import list_dead_ends

    # Given: one infrastructure-failing track and one productive sibling.
    runner = _runner_with_real_kb(tmp_path)

    def fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        prompt = cmd[2]
        if "boom" in prompt:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=11)
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                '<FINDINGS>[{"type":"nfs-export","endpoint":"/srv","method":"GET",'
                '"payload":"","evidence":"export listed","confidence":"high",'
                '"source":"test"}]</FINDINGS>'
            ),
            stderr="",
        )

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: fan-out runs both tracks.
    result = runner.fan_out([("boom", "blow up"), ("nfs", "Enumerate NFS exports")], timeout=11)

    # Then: the sibling finishes and the infrastructure error never becomes memory.
    assert result["merged"] == 1
    assert set(result["responses"]) == {"nfs"}
    assert result["agent_errors"]["boom"]["type"] == "timeout"
    assert result["agent_errors"]["boom"]["label"] == "boom"
    assert result["dead_ends_recorded"] == 0
    assert result["dead_ends_cleared"] == 0
    assert list_dead_ends(runner.kb, host=runner.scanner.host) == []
    assert any(f["type"] == "nfs-export" for f in runner.scanner.findings)


def test_fan_out_internal_track_error_reports_agent_error_without_dead_end_poisoning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bugbounty_ctf.recon import list_dead_ends

    # Given: one worker raises a generic bug while a sibling reports a finding.
    runner = _runner_with_real_kb(tmp_path)
    long_detail = "x" * 800

    def fake_run(prompt: str, *, timeout: int, label: str = "agent") -> str:
        if label == "boom":
            raise RuntimeError(f"track exploded {long_detail}")
        return (
            '<FINDINGS>[{"type":"nfs-export","endpoint":"/srv","method":"GET",'
            '"payload":"","evidence":"export listed","confidence":"high",'
            '"source":"test"}]</FINDINGS>'
        )

    monkeypatch.setattr(runner, "_run_hermes", fake_run)

    # When: fan-out runs both tracks.
    result = runner.fan_out([("boom", "blow up"), ("nfs", "Enumerate NFS exports")])

    # Then: the generic error is internal, omitted from responses, and not recorded as memory.
    assert result["merged"] == 1
    assert set(result["responses"]) == {"nfs"}
    assert result["agent_errors"]["boom"] == {
        "type": "internal_error",
        "label": "boom",
        "returncode": None,
        "timeout": None,
        "stderr": f"RuntimeError: track exploded {long_detail}"[:500],
    }
    assert result["dead_ends_recorded"] == 0
    assert result["dead_ends_cleared"] == 0
    assert list_dead_ends(runner.kb, host=runner.scanner.host) == []
    assert any(f["type"] == "nfs-export" for f in runner.scanner.findings)


def test_run_with_agents_invalid_verifier_votes_become_unverified_without_writeback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a phase reports a finding, but every verifier response is invalid.
    runner = _runner(tmp_path)
    writeback_inputs: list[list[dict[str, Any]]] = []

    def fake_hermes(prompt: str, *, timeout: int, label: str = "agent") -> str:
        if "REFUTE" in prompt:
            return "no verdict block"
        return (
            '<FINDINGS>[{"type":"sqli","endpoint":"/login","method":"POST",'
            '"payload":"\'","evidence":"SQL error","confidence":"high",'
            '"source":"test"}]</FINDINGS>'
        )

    def record_lessons(findings: list[dict[str, Any]]) -> int:
        writeback_inputs.append(findings)
        return 0

    monkeypatch.setattr(runner, "_run_hermes", fake_hermes)
    monkeypatch.setattr(runner, "_writeback_lessons", record_lessons)
    monkeypatch.setattr(runner, "_writeback_pattern", lambda findings: None)
    monkeypatch.setattr(runner, "_score_pattern_feedback", lambda findings, *, now: {})
    monkeypatch.setattr(runner, "save_results", lambda *args, **kwargs: None)

    # When: verification cannot produce a complete valid panel.
    result = runner.run_with_agents(verify=True, verify_votes=3)

    # Then: the finding is unverified, not confirmed, and not written back.
    assert result["confirmed_findings"] == []
    assert result["refuted_findings"] == []
    assert [f["type"] for f in result["unverified_findings"]] == ["sqli"]
    assert result["verification"][0]["verified"] is False
    assert result["verification"][0]["refuted"] is False
    assert result["verification"][0]["invalid_votes"] == 3
    assert result["verification"][0]["votes"] == []
    assert writeback_inputs == [[]]


def test_partial_verifier_timeout_makes_finding_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: two valid verifier votes and one timeout.
    runner = _runner(tmp_path)
    calls: list[int] = []

    def fake_run(*args: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append(len(calls) + 1)
        if len(calls) == 3:
            raise subprocess.TimeoutExpired(cmd="hermes", timeout=6)
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout='<VERDICT>{"refuted": false, "reason": "reproduced"}</VERDICT>',
            stderr="",
        )

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: the verifier panel is incomplete.
    result = runner.verify_finding({"type": "sqli", "endpoint": "/login"}, votes=3, timeout=6)

    # Then: valid votes are retained but the finding is explicitly unverified.
    assert result["verified"] is False
    assert result["refuted"] is False
    assert len(result["votes"]) == 2
    assert result["invalid_votes"] == 0
    assert len(result["agent_errors"]) == 1
    assert result["agent_errors"][0]["type"] == "timeout"
