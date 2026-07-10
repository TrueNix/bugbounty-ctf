"""Tests for the NFS and mail enumeration modules."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from bugbounty_ctf.execenv import HostEnv, KaliEnv
from bugbounty_ctf.mail_enum import MailEnumerator, extract_secrets
from bugbounty_ctf.nfs_enum import NFSEnumerator, NFSExport


class FakeEnv:
    """A scripted ExecEnv stub — never touches real docker/host mount.

    ``run`` returns a CompletedProcess matched by a substring of the argv;
    ``host_path`` echoes the container path through a ``host_root`` prefix.
    """

    def __init__(self, host_root: str = "/host") -> None:
        self.host_root = host_root
        self.calls: list[list[str]] = []
        self._scripts: list[tuple[str, subprocess.CompletedProcess[str]]] = []

    def reply(self, contains: str, *, stdout: str = "", stderr: str = "", rc: int = 0) -> None:
        self._scripts.append(
            (
                contains,
                subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr),
            )
        )

    def run(
        self, argv: Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        cmd = list(argv)
        self.calls.append(cmd)
        joined = " ".join(cmd)
        for contains, resp in self._scripts:
            if contains in joined:
                return resp
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    def host_path(self, container_path: str) -> str:
        return self.host_root + container_path


class FakeKaliEnv(KaliEnv):
    """A KaliEnv whose ``run`` is scripted and whose workdir is a tmp dir.

    Bypasses real docker entirely: matches argv substrings to canned
    CompletedProcess replies so ``mount_and_scan`` can be exercised with no
    container, and writes the host-side scanner copy into ``workdir`` (tmp_path).
    """

    def __init__(self, workdir: str) -> None:
        self._workdir = workdir
        self.calls: list[list[str]] = []
        self._scripts: list[tuple[str, subprocess.CompletedProcess[str]]] = []

    @property
    def workdir(self) -> str:
        return self._workdir

    def reply(self, contains: str, *, stdout: str = "", stderr: str = "", rc: int = 0) -> None:
        self._scripts.append(
            (
                contains,
                subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr),
            )
        )

    def run(
        self, argv: Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        cmd = list(argv)
        self.calls.append(cmd)
        joined = " ".join(cmd)
        for contains, resp in self._scripts:
            if contains in joined:
                return resp
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")


class RecordingHostEnv(HostEnv):
    def __init__(self, *, write_key: bool = False, error: OSError | None = None) -> None:
        self.calls: list[list[str]] = []
        self.write_key = write_key
        self.error = error

    def run(
        self, argv: Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        if self.error is not None:
            raise self.error
        cmd = list(argv)
        self.calls.append(cmd)
        if self.write_key:
            mountpoint = Path(cmd[-1])
            (mountpoint / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="")


class TestNFSEnumerator:
    def test_rejects_bad_host(self) -> None:
        with pytest.raises(ValueError):
            NFSEnumerator("evil; rm -rf /", env=FakeEnv())

    def test_candidate_mounts_adds_parents_and_roots(self) -> None:
        nfs = NFSEnumerator("10.0.0.1", env=FakeEnv())
        cands = nfs.candidate_mounts([NFSExport(path="/srv/nfs/onboarding")])
        assert "/srv/nfs/onboarding" in cands
        assert "/srv/nfs" in cands  # parent, often unadvertised
        assert "/srv" in cands
        assert "/home" in cands  # common root

    def test_list_exports_parses_showmount(self) -> None:
        env = FakeEnv()
        env.reply(
            "showmount",
            stdout="Export list for 10.0.0.1:\n/srv/nfs/onboarding *\n/home 10.0.0.0/24\n",
        )
        nfs = NFSEnumerator("10.0.0.1", env=env)
        exports = nfs.list_exports()
        paths = {e.path for e in exports}
        assert paths == {"/srv/nfs/onboarding", "/home"}
        assert any("showmount" in " ".join(c) for c in env.calls)

    def test_try_mount_runs_in_env(self) -> None:
        env = FakeEnv()
        env.reply("mount", rc=0)
        nfs = NFSEnumerator("10.0.0.1", env=env)
        result = nfs.try_mount("/srv/nfs/onboarding", "/work/nfs")
        assert result["mounted"] is True
        assert result["remote"] == "10.0.0.1:/srv/nfs/onboarding"
        assert result["mountpoint"] == "/work/nfs"
        mount_call = next(c for c in env.calls if "mount" in c)
        assert "/work/nfs" in mount_call  # mountpoint interpreted in the env

    def test_try_mount_reports_error_without_raising(self) -> None:
        env = FakeEnv()
        env.reply("mount", rc=32, stderr="access denied")
        nfs = NFSEnumerator("10.0.0.1", env=env)
        result = nfs.try_mount("/srv/nfs/onboarding", "/work/nfs")
        assert result["mounted"] is False
        assert result["error"] == "access denied"

    def test_mount_and_scan_runs_scanner_in_container(self, tmp_path: Path) -> None:
        # KaliEnv path: mount succeeds; the in-container python3 _nfs_scan.py call
        # returns a JSON report on stdout, which mount_and_scan parses and returns.
        report_payload = {
            "root": "/mnt/nfs_nfs",
            "ssh_keys": [{"path": "/mnt/nfs_nfs/id_rsa", "uid": 1000}],
            "secrets": [],
            "uid_locked": [],
            "interesting": [{"path": "/mnt/nfs_nfs/id_rsa", "uid": 1000}],
        }
        env = FakeKaliEnv(str(tmp_path))
        env.reply("mount", rc=0)
        env.reply("_nfs_scan.py", stdout=json.dumps(report_payload), rc=0)
        nfs = NFSEnumerator("10.0.0.1", env=env)

        report = nfs.mount_and_scan("/srv/nfs/onboarding")

        assert report["mount"]["mounted"] is True
        # Mounted at /mnt/nfs_* (NOT /work) so it does not land on the bind mount.
        mount_call = next(
            c for c in env.calls if "mount" in c and "_nfs_scan.py" not in " ".join(c)
        )
        assert "/mnt/nfs_nfs" in mount_call
        # The scanner script was copied host-side into workdir (= tmp_path).
        assert (tmp_path / "_nfs_scan.py").exists()
        # Scanner was invoked in-container against the /mnt mountpoint.
        scan_call = next(c for c in env.calls if "_nfs_scan.py" in " ".join(c))
        assert scan_call == ["python3", "/work/_nfs_scan.py", "/mnt/nfs_nfs"]
        assert report["scan"] == report_payload

    def test_mount_and_scan_kali_scan_none_on_unparseable(self, tmp_path: Path) -> None:
        env = FakeKaliEnv(str(tmp_path))
        env.reply("mount", rc=0)
        env.reply("_nfs_scan.py", stdout="not json", rc=0)
        nfs = NFSEnumerator("10.0.0.1", env=env)
        report = nfs.mount_and_scan("/srv/nfs/onboarding")
        assert report["mount"]["mounted"] is True
        assert report["scan"] is None

    def test_mount_and_scan_kali_skips_scan_when_mount_fails(self, tmp_path: Path) -> None:
        env = FakeKaliEnv(str(tmp_path))
        env.reply("mount", rc=32, stderr="denied")
        nfs = NFSEnumerator("10.0.0.1", env=env)
        report = nfs.mount_and_scan("/srv/nfs/onboarding")
        assert report["mount"]["mounted"] is False
        assert report["scan"] is None
        # No scanner invocation when the mount failed.
        assert not any("_nfs_scan.py" in " ".join(c) for c in env.calls)

    def test_mount_and_scan_host_env_scans_directly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        monkeypatch.setattr(tempfile, "tempdir", None)

        env = RecordingHostEnv(write_key=True)
        nfs = NFSEnumerator("10.0.0.1", env=env)
        report = nfs.mount_and_scan("/srv/nfs/onboarding", name="share")

        assert report["mount"]["mounted"] is True
        mountpoint = Path(report["mount"]["mountpoint"])
        assert mountpoint.is_relative_to(tmp_path)
        assert mountpoint.name == "share"
        assert not str(mountpoint).startswith(KaliEnv.container_workdir)
        assert mountpoint.exists()
        mount_call = next(c for c in env.calls if "mount" in c)
        assert str(mountpoint) in mount_call
        assert report["scan"] is not None
        names = {os.path.basename(e["path"]) for e in report["scan"]["ssh_keys"]}
        assert "id_rsa" in names

    def test_mount_and_scan_host_env_rejects_name_traversal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TMPDIR", str(tmp_path))
        monkeypatch.setattr(tempfile, "tempdir", None)

        env = RecordingHostEnv()
        nfs = NFSEnumerator("10.0.0.1", env=env)

        report = nfs.mount_and_scan("/srv/nfs/onboarding", name="../escape")

        assert report["mount"]["mounted"] is False
        assert report["scan"] is None
        assert "Invalid mount name" in report["mount"]["error"]
        assert env.calls == []

    def test_try_mount_reports_directory_creation_error_without_raising(
        self, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "blocker"
        blocker.write_text("not a directory")

        env = RecordingHostEnv()
        nfs = NFSEnumerator("10.0.0.1", env=env)

        result = nfs.try_mount("/srv/nfs/onboarding", str(blocker / "share"))

        assert result["mounted"] is False
        assert "mountpoint directory error" in result["error"]
        assert env.calls == []

    def test_try_mount_reports_command_os_error_without_raising(self, tmp_path: Path) -> None:
        nfs = NFSEnumerator(
            "10.0.0.1", env=RecordingHostEnv(error=PermissionError("mount exec denied"))
        )

        result = nfs.try_mount("/srv/nfs/onboarding", str(tmp_path / "share"))

        assert result["mounted"] is False
        assert "mount exec denied" in result["error"]

    def test_scan_dir_flags_ssh_keys_and_secrets(self, tmp_path: Path) -> None:
        (tmp_path / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")
        (tmp_path / "notes.txt").write_text("the db password=hunter2 is here")
        (tmp_path / "boring.txt").write_text("hello world")
        report = NFSEnumerator.scan_dir(str(tmp_path))
        names = {os.path.basename(e["path"]) for e in report["interesting"]}
        assert "id_rsa" in names and "notes.txt" in names and "boring.txt" not in names
        assert any(os.path.basename(e["path"]) == "id_rsa" for e in report["ssh_keys"])

    def test_scan_dir_reports_uid_locked(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "id_rsa"
        secret.write_text("KEY")
        # Simulate the file being unreadable (owned by another UID on the share).
        real_access = os.access
        monkeypatch.setattr(
            os, "access", lambda p, m: False if str(p) == str(secret) else real_access(p, m)
        )
        report = NFSEnumerator.scan_dir(str(tmp_path))
        assert any(e["path"] == str(secret) for e in report["uid_locked"])


# ---- a tiny fake IMAP client so mail tests need no live server ----
class _FakeIMAP:
    def __init__(self, valid: dict[str, str], mailboxes: dict[str, list[bytes]]) -> None:
        self.valid = valid
        self.mailboxes = mailboxes
        self.user: str | None = None
        self._sel: str | None = None
        self.sock = type("S", (), {"settimeout": lambda self, t: None})()

    def login(self, user: str, pw: str) -> Any:
        if self.valid.get(user) == pw:
            self.user = user
            return ("OK", [b"ok"])
        raise Exception("auth failed")

    def select(self, box: str, readonly: bool = False) -> Any:
        if box in self.mailboxes:
            self._sel = box
            return ("OK", [b"1"])
        return ("NO", [b"no such"])

    def search(self, charset: Any, *criteria: str) -> Any:
        msgs = self.mailboxes.get(self._sel or "", [])
        return ("OK", [b" ".join(str(i + 1).encode() for i in range(len(msgs)))])

    def fetch(self, mid: bytes, spec: str) -> Any:
        idx = int(mid) - 1
        msgs = self.mailboxes.get(self._sel or "", [])
        return ("OK", [(b"x", msgs[idx])])

    def logout(self) -> Any:
        return ("BYE", [b"bye"])


_RAW_WITH_KEY = (
    b"From: it@corp\r\nTo: kevin@corp\r\nSubject: your key\r\n\r\n"
    b"Here you go:\r\n-----BEGIN OPENSSH PRIVATE KEY-----\r\nAAAAdeadbeef\r\n"
    b"-----END OPENSSH PRIVATE KEY-----\r\npassword: Sup3rSecret\r\n"
)


class TestMailEnumerator:
    def test_extract_secrets(self) -> None:
        found = extract_secrets(_RAW_WITH_KEY.decode())
        assert found["private_keys"] and "OPENSSH PRIVATE KEY" in found["private_keys"][0]
        assert any("Sup3rSecret" in c for c in found["credentials"])

    def test_spray_finds_valid_concurrently(self) -> None:
        valid = {"kevin": "Welcome2024!"}
        me = MailEnumerator("h", client_factory=lambda: _FakeIMAP(valid, {}))
        hits = me.spray(["kevin", "sarah", "it"], ["Welcome2024!", "wrong"], workers=4)
        assert hits == [("kevin", "Welcome2024!")]

    def test_try_login(self) -> None:
        me = MailEnumerator("h", client_factory=lambda: _FakeIMAP({"a": "b"}, {}))
        assert me.try_login("a", "b") is True
        assert me.try_login("a", "x") is False

    def test_harvest_extracts_key_from_mailbox(self) -> None:
        boxes = {"INBOX": [_RAW_WITH_KEY]}
        me = MailEnumerator("h", client_factory=lambda: _FakeIMAP({"kevin": "pw"}, boxes))
        loot = me.harvest("kevin", "pw", folders=["INBOX"])
        assert loot["private_keys"] and loot["messages"][0]["subject"] == "your key"
        assert any("Sup3rSecret" in c for c in loot["credentials"])
