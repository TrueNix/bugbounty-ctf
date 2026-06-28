"""Tests for the ExecEnv execution-substrate layer.

No real Docker, host mount, or network: HostEnv's subprocess.run is
monkeypatched and KaliEnv is driven through a KaliBox with an injected fake
runtime runner.
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from bugbounty_ctf.execenv import ExecEnv, HostEnv, KaliEnv, default_exec_env
from bugbounty_ctf.kalibox import KaliBox


class FakeRuntime:
    """Records runtime invocations and returns scripted responses."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.default = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

    def __call__(
        self, cmd: list[str], *, timeout: float | None = None, input: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        return self.default


class TestHostEnv:
    def test_runs_argv_via_subprocess_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            captured["argv"] = argv
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(args=argv, returncode=0, stdout="hi", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        env = HostEnv()
        result = env.run(["echo", "hi"], timeout=5)

        assert result.stdout == "hi"
        assert captured["argv"] == ["echo", "hi"]  # list-form, no shell
        assert captured["kwargs"]["capture_output"] is True
        assert captured["kwargs"]["text"] is True
        assert captured["kwargs"]["timeout"] == 5

    def test_satisfies_execenv_protocol(self) -> None:
        assert isinstance(HostEnv(), ExecEnv)


class TestKaliEnv:
    def test_run_starts_box_and_delegates_to_exec_raw(self) -> None:
        fake = FakeRuntime()
        box = KaliBox(runner=fake, workdir="/tmp/kalibox-test-work")
        env = KaliEnv(box)

        result = env.run(["mount", "-t", "nfs", "10.0.0.1:/srv/x", "/work/nfs"], timeout=25)

        assert result.returncode == 0
        # The box was started (a state-check call happened) and the argv was
        # delegated to exec_raw → `docker exec kalibox <argv>`.
        exec_call = next(c for c in fake.calls if "exec" in c)
        assert exec_call[:3] == ["docker", "exec", "kalibox"]
        assert exec_call[-1] == "/work/nfs"
        assert "bash" not in exec_call  # literal argv, no shell wrapper

    def test_default_box_when_none(self) -> None:
        env = KaliEnv()
        assert isinstance(env.box, KaliBox)

    def test_host_path_maps_work_subpath(self) -> None:
        box = KaliBox(runner=FakeRuntime(), workdir="/home/u/.hermes/kalibox/work")
        env = KaliEnv(box)
        assert env.host_path("/work/nfs") == "/home/u/.hermes/kalibox/work/nfs"
        assert env.host_path("/work/a/b") == "/home/u/.hermes/kalibox/work/a/b"

    def test_host_path_maps_work_root(self) -> None:
        box = KaliBox(runner=FakeRuntime(), workdir="/w")
        env = KaliEnv(box)
        assert env.host_path("/work") == "/w"

    def test_host_path_rejects_non_work_path(self) -> None:
        env = KaliEnv(KaliBox(runner=FakeRuntime()))
        with pytest.raises(ValueError):
            env.host_path("/etc/passwd")

    def test_satisfies_execenv_protocol(self) -> None:
        assert isinstance(KaliEnv(KaliBox(runner=FakeRuntime())), ExecEnv)


class TestDefaultExecEnv:
    def test_returns_kali_env(self) -> None:
        assert isinstance(default_exec_env(), KaliEnv)
