"""Tests for the kalibox isolated-Kali-container execution layer.

The container runtime is fully mocked via an injectable runner, so these run
without Docker/Podman and never pull an image or start a container.
"""

from __future__ import annotations

import subprocess
from typing import Any

import pytest

from bugbounty_ctf.kalibox import DEFAULT_NAME, KaliBox, main


class FakeRuntime:
    """Records every runtime invocation and returns scripted responses."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.responses: dict[tuple[str, ...], subprocess.CompletedProcess[str]] = {}
        self.default = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

    def reply(self, match: tuple[str, ...], *, stdout: str = "", rc: int = 0) -> None:
        self.responses[match] = subprocess.CompletedProcess(
            args=list(match), returncode=rc, stdout=stdout, stderr=""
        )

    def __call__(
        self, cmd: list[str], *, timeout: float | None = None, input: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(cmd)
        for match, resp in self.responses.items():
            if all(tok in cmd for tok in match):
                return resp
        return self.default

    def last(self) -> list[str]:
        return self.calls[-1]


@pytest.fixture
def fake() -> FakeRuntime:
    return FakeRuntime()


@pytest.fixture
def box(fake: FakeRuntime) -> KaliBox:
    return KaliBox(runner=fake, workdir="/tmp/kalibox-test-work")


class TestValidation:
    def test_rejects_bad_container_name(self) -> None:
        with pytest.raises(ValueError):
            KaliBox(name="../evil")

    def test_rejects_bad_runtime(self) -> None:
        with pytest.raises(ValueError):
            KaliBox(runtime="rm -rf")

    def test_defaults(self, box: KaliBox) -> None:
        assert box.name == DEFAULT_NAME
        assert box.runtime == "docker"


class TestState:
    def test_is_running_true(self, box: KaliBox, fake: FakeRuntime) -> None:
        fake.reply(("ps", "--format"), stdout="kalibox\n")
        assert box.is_running() is True

    def test_is_running_false_when_absent(self, box: KaliBox) -> None:
        assert box.is_running() is False

    def test_status_shape(self, box: KaliBox) -> None:
        st = box.status()
        assert st["name"] == "kalibox" and st["runtime"] == "docker"
        assert "running" in st and "workdir" in st


class TestStart:
    def test_start_runs_privileged_host_net_container(
        self, box: KaliBox, fake: FakeRuntime
    ) -> None:
        # Not running, doesn't exist, image present → must `run` a new container.
        fake.reply(("images", "-q"), stdout="sha256:abc\n")
        box.start()
        run_cmd = next(c for c in fake.calls if "run" in c)
        assert "--privileged" in run_cmd
        assert "host" in run_cmd and "--network" in run_cmd
        assert "kalibox" in run_cmd
        assert "/tmp/kalibox-test-work:/work" in run_cmd
        assert run_cmd[-2:] == ["sleep", "infinity"]

    def test_start_pulls_when_image_missing(self, box: KaliBox, fake: FakeRuntime) -> None:
        # images -q returns empty → must pull before run.
        box.start()
        assert any("pull" in c for c in fake.calls)

    def test_start_noop_when_running(self, box: KaliBox, fake: FakeRuntime) -> None:
        fake.reply(("ps", "--format"), stdout="kalibox\n")
        box.start()
        assert not any("run" in c for c in fake.calls)

    def test_start_restarts_existing_stopped(self, box: KaliBox, fake: FakeRuntime) -> None:
        # Exists (ps -a) but not running → `start`, never `run`.
        fake.reply(("ps", "-a", "--format"), stdout="kalibox\n")
        box.start()
        assert any(c[:2] == ["docker", "start"] for c in fake.calls)
        assert not any("run" in c for c in fake.calls)


class TestProvision:
    def test_provision_skips_when_marker_present(self, box: KaliBox, fake: FakeRuntime) -> None:
        fake.reply(("exec", "test", "-f"), rc=0)  # marker exists
        assert box.provision() is False
        assert not any("apt-get" in " ".join(c) for c in fake.calls)

    def test_provision_installs_when_missing(self, box: KaliBox, fake: FakeRuntime) -> None:
        fake.reply(("exec", "test", "-f"), rc=1)  # marker missing
        assert box.provision() is True
        install = next(c for c in fake.calls if "apt-get" in " ".join(c))
        joined = " ".join(install)
        assert "nmap" in joined and "nfs-common" in joined
        # Marker is written so subsequent provisions short-circuit.
        assert "touch" in joined and ".kalibox-provisioned" in joined


class TestExecution:
    def test_run_string_uses_bash_lc(self, box: KaliBox, fake: FakeRuntime) -> None:
        box.run("nmap -sV 10.129.33.77")
        cmd = fake.last()
        assert cmd[:3] == ["docker", "exec", "kalibox"]
        assert cmd[3:5] == ["bash", "-lc"]
        assert cmd[-1] == "nmap -sV 10.129.33.77"

    def test_run_list_is_literal_argv(self, box: KaliBox, fake: FakeRuntime) -> None:
        box.run(["mount", "-t", "nfs", "10.129.33.77:/srv/x", "/work/nfs"])
        cmd = fake.last()
        assert cmd[:3] == ["docker", "exec", "kalibox"]
        # No bash wrapper — argv passed literally (injection-safe).
        assert "bash" not in cmd
        assert cmd[-1] == "/work/nfs"

    def test_run_propagates_output_and_rc(self, box: KaliBox, fake: FakeRuntime) -> None:
        fake.reply(("exec", "kalibox"), stdout="PORT 22 open\n", rc=0)
        r = box.run("nmap 10.129.33.77")
        assert r.returncode == 0 and "22 open" in r.stdout


class TestFileTransfer:
    def test_cp_out(self, box: KaliBox, fake: FakeRuntime) -> None:
        box.cp_out("/work/loot.txt", "/tmp/loot.txt")
        assert fake.last() == ["docker", "cp", "kalibox:/work/loot.txt", "/tmp/loot.txt"]

    def test_cp_in(self, box: KaliBox, fake: FakeRuntime) -> None:
        box.cp_in("/tmp/exploit.py", "/work/exploit.py")
        assert fake.last() == ["docker", "cp", "/tmp/exploit.py", "kalibox:/work/exploit.py"]


class TestFailClosed:
    def test_missing_runtime_raises(self) -> None:
        def boom(*a: Any, **k: Any) -> Any:
            raise FileNotFoundError("docker")

        box = KaliBox(runner=boom)
        with pytest.raises(KaliBox.DockerNotFoundError):
            box.is_running()


class TestCli:
    def test_help_returns_zero(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["--help"]) == 0
        assert "kalibox" in capsys.readouterr().out

    def test_status_subcommand(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        fake = FakeRuntime()
        # main() builds its own KaliBox → patch the default runner it uses.
        import bugbounty_ctf.kalibox as kb

        monkeypatch.setattr(kb, "_default_runner", fake)
        rc = main(["status"])
        assert rc == 0
        assert "name: kalibox" in capsys.readouterr().out

    def test_command_passthrough_returns_rc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = FakeRuntime()
        fake.reply(("exec", "test", "-f"), rc=0)  # already provisioned
        fake.reply(("exec", "kalibox", "bash"), stdout="ok\n", rc=0)
        import bugbounty_ctf.kalibox as kb

        monkeypatch.setattr(kb, "_default_runner", fake)
        assert main(["nmap", "10.129.33.77"]) == 0
