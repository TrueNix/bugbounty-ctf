from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from bugbounty_ctf import skill_runner
from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.scope import ScopeGuard
from bugbounty_ctf.skill_runner import SkillOrchestrator


class _FakeKB:
    def search(self, query: str, limit: int = 5) -> list[dict[str, str]]:
        return []

    def suggest_methodology(self, tech: list[str]) -> list[dict[str, str]]:
        return []


def _runner_with_context(tmp_path: Path) -> SkillOrchestrator:
    scanner = SecurityScanner(
        "https://target.test/",
        state_file=str(tmp_path / "parent-state.json"),
        db=ScannerDB(str(tmp_path / "parent.db")),
        timeout=3.5,
        delay=0.75,
        respect_waf=False,
        verify=True,
        scope=ScopeGuard(["target.test"], allow_subdomains=False),
        headers={
            "Host": "secret-vhost.target.test",
            "Authorization": "Bearer secret-auth-token",
        },
    )
    scanner.session.cookies.set("sessionid", "secret-cookie-value")
    return SkillOrchestrator("https://target.test/", scanner=scanner, knowledge_base=_FakeKB())


def _first_python_block(prompt: str) -> str:
    fence = "```python\n"
    start = prompt.index(fence) + len(fence)
    end = prompt.index("\n```", start)
    return prompt[start:end]


def _scanner_from_bootstrap(
    prompt: str, context_json: str, monkeypatch: pytest.MonkeyPatch
) -> SecurityScanner:
    monkeypatch.setenv(skill_runner.SCANNER_CONTEXT_ENV, context_json)
    namespace: dict[str, object] = {}
    exec(_first_python_block(prompt), namespace)
    scanner = namespace["scanner"]
    assert isinstance(scanner, SecurityScanner)
    return scanner


def test_phase_agent_context_travels_in_env_without_prompt_or_argv_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a parent scanner with vhost, auth, cookie, scope, and non-default request settings.
    runner = _runner_with_context(tmp_path)
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: a phase agent is spawned through the real runner path.
    assert runner.spawn_agent(runner.get_recon_guidance()) == "ok"

    # Then: the subprocess gets list-form argv and the request context in env only.
    cmd = captured["cmd"]
    env = captured["env"]
    assert isinstance(cmd, list)
    assert isinstance(env, dict)
    assert cmd[:2] == ["hermes", "-z"]
    assert env["HERMES_NO_STREAM"] == "1"

    context_json = env[skill_runner.SCANNER_CONTEXT_ENV]
    assert isinstance(context_json, str)
    context = json.loads(context_json)
    assert context["cookies"] == {"sessionid": "secret-cookie-value"}
    assert context["db_path"] == str(tmp_path / "parent.db")
    assert context["delay"] == 0.75
    assert context["headers"]["Authorization"] == "Bearer secret-auth-token"
    assert context["headers"]["Host"] == "secret-vhost.target.test"
    assert context["respect_waf"] is False
    assert context["scope"] == {"allow_subdomains": False, "allowed": ["target.test"]}
    assert context["state_file"] == str(tmp_path / "parent-state.json")
    assert context["target_url"] == "https://target.test"
    assert context["timeout"] == 3.5
    assert context["verify"] is True

    argv_blob = json.dumps(cmd)
    prompt = cmd[2]
    assert isinstance(prompt, str)
    for secret in ("secret-vhost.target.test", "Bearer secret-auth-token", "secret-cookie-value"):
        assert secret not in argv_blob
        assert secret not in prompt

    # Then: executing the child bootstrap reconstructs the same scanner request fields.
    child = _scanner_from_bootstrap(prompt, context_json, monkeypatch)
    assert child.session.headers["Host"] == "secret-vhost.target.test"
    assert child.session.headers["Authorization"] == "Bearer secret-auth-token"
    assert child.session.cookies.get("sessionid") == "secret-cookie-value"
    assert child.timeout == 3.5
    assert child.delay == 0.75
    assert child.respect_waf is False
    assert child.verify is True
    assert child.session.verify is True
    assert child.state_file == str(tmp_path / "parent-state.json")
    assert child.db.db_path == str(tmp_path / "parent.db")
    assert child.scope is not None
    assert child.scope.is_allowed("https://target.test/")
    assert not child.scope.is_allowed("https://sub.target.test/")


def test_verify_prompt_uses_same_env_bootstrap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: the same protected scanner context and a verifier vote.
    runner = _runner_with_context(tmp_path)
    prompts: list[str] = []

    def fake_run(prompt: str, *, timeout: int, label: str = "agent") -> str:
        prompts.append(prompt)
        return '<VERDICT>{"refuted": false, "reason": "reproduced"}</VERDICT>'

    monkeypatch.setattr(runner, "_run_hermes", fake_run)

    # When: the adversarial verifier is spawned.
    result = runner.verify_finding({"type": "sqli", "endpoint": "/login"}, votes=1)

    # Then: its prompt has the same environment bootstrap and still redacts secrets.
    assert result["refuted"] is False
    prompt = prompts[0]
    assert skill_runner.SCANNER_CONTEXT_ENV in prompt
    context_json = runner._scanner_context_json()
    for secret in ("secret-vhost.target.test", "Bearer secret-auth-token", "secret-cookie-value"):
        assert secret not in prompt

    child = _scanner_from_bootstrap(prompt, context_json, monkeypatch)
    assert child.session.headers["Host"] == "secret-vhost.target.test"
    assert child.session.cookies.get("sessionid") == "secret-cookie-value"


def test_agent_context_supports_absent_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a parent scanner without a ScopeGuard.
    scanner = SecurityScanner(
        "http://target.test/",
        state_file=str(tmp_path / "state.json"),
        db=ScannerDB(str(tmp_path / "scanner.db")),
    )
    runner = SkillOrchestrator("http://target.test/", scanner=scanner, knowledge_base=_FakeKB())
    captured: dict[str, object] = {}

    def fake_run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = cmd
        captured["env"] = kwargs["env"]
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(skill_runner.subprocess, "run", fake_run)

    # When: an agent is spawned.
    assert runner.spawn_agent(runner.get_recon_guidance()) == "ok"

    # Then: scope=None is serialized and reconstructed as no guard.
    env = captured["env"]
    assert isinstance(env, dict)
    context_json = env[skill_runner.SCANNER_CONTEXT_ENV]
    assert isinstance(context_json, str)
    assert json.loads(context_json)["scope"] is None

    cmd = captured["cmd"]
    assert isinstance(cmd, list)
    prompt = cmd[2]
    assert isinstance(prompt, str)
    child = _scanner_from_bootstrap(prompt, context_json, monkeypatch)
    assert child.scope is None
