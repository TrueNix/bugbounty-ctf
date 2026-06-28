"""Tests for the standalone, stdlib-only NFS share scanner."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from bugbounty_ctf import nfs_scan


def test_scan_flags_ssh_keys_and_secrets(tmp_path: Path) -> None:
    (tmp_path / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")
    (tmp_path / "notes.txt").write_text("the db password=hunter2 is here")
    (tmp_path / "boring.txt").write_text("hello world")

    report = nfs_scan.scan(str(tmp_path))

    names = {os.path.basename(e["path"]) for e in report["interesting"]}
    assert "id_rsa" in names and "notes.txt" in names and "boring.txt" not in names
    assert any(os.path.basename(e["path"]) == "id_rsa" for e in report["ssh_keys"])
    assert report["root"] == str(tmp_path)


def test_scan_reports_uid_locked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = tmp_path / "id_rsa"
    secret.write_text("KEY")
    real_access = os.access
    monkeypatch.setattr(
        os, "access", lambda p, m: False if str(p) == str(secret) else real_access(p, m)
    )

    report = nfs_scan.scan(str(tmp_path))

    assert any(e["path"] == str(secret) for e in report["uid_locked"])


def test_scan_has_no_package_imports() -> None:
    # The module must be runnable copied into the container with zero deps.
    src = Path(nfs_scan.__file__).read_text()
    assert "import bugbounty_ctf" not in src
    assert "from bugbounty_ctf" not in src
    assert 'if __name__ == "__main__":' in src
