"""Tests for the NFS and mail enumeration modules."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from bugbounty_ctf.mail_enum import MailEnumerator, extract_secrets
from bugbounty_ctf.nfs_enum import NFSEnumerator, NFSExport


class TestNFSEnumerator:
    def test_rejects_bad_host(self) -> None:
        with pytest.raises(ValueError):
            NFSEnumerator("evil; rm -rf /")

    def test_candidate_mounts_adds_parents_and_roots(self) -> None:
        nfs = NFSEnumerator("10.0.0.1")
        cands = nfs.candidate_mounts([NFSExport(path="/srv/nfs/onboarding")])
        assert "/srv/nfs/onboarding" in cands
        assert "/srv/nfs" in cands  # parent, often unadvertised
        assert "/srv" in cands
        assert "/home" in cands  # common root

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
