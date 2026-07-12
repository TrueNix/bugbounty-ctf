"""Tests for the scope-compliance audit trail."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from bugbounty_ctf.audit_log import AuditError, AuditLog


def test_summary_counts_pass_fail_skip(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.log_request("https://api.example.com/a", "GET", "pass", response_status=200)
    log.log_request("https://evil.test/x", "POST", "fail")
    log.log_request("https://unscoped.test/y", "GET", "skip")

    summary = log.summary()

    assert summary.total == 3
    assert (summary.passed, summary.failed, summary.skipped) == (1, 1, 1)
    assert summary.out_of_scope_hosts == ("evil.test",)
    assert summary.clean is False


def test_clean_summary_when_no_failures(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.log_request("https://api.example.com/a", "GET", "pass")

    assert log.summary().clean is True


def test_method_is_normalized_and_metadata_stamped(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    entry = log.log_request("https://api.example.com/a", "get", "pass")

    assert entry["method"] == "GET"
    assert entry["schema_version"] == 1
    assert entry["ts"].endswith("Z")


def test_session_id_from_argument_and_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = AuditLog(tmp_path / "a.jsonl", session_id="sess-arg")
    assert log.log_request("https://x.test/", "GET", "pass")["session_id"] == "sess-arg"

    monkeypatch.setenv("HERMES_SESSION_ID", "sess-env")
    env_log = AuditLog(tmp_path / "b.jsonl")
    assert env_log.log_request("https://x.test/", "GET", "pass")["session_id"] == "sess-env"


@pytest.mark.parametrize(
    ("url", "method", "scope_check"),
    [
        ("https://x.test/", "GET", "bogus"),
        ("https://x.test/", "FETCH", "pass"),
        ("", "GET", "pass"),
    ],
)
def test_validation_fails_closed(
    tmp_path: Path, url: str, method: str, scope_check: str
) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(AuditError):
        log.log_request(url, method, scope_check)


def test_read_all_skips_corrupted_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.log_request("https://api.example.com/a", "GET", "pass")
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{ not json\n")
    log.log_request("https://api.example.com/b", "GET", "pass")

    assert len(log.read_all()) == 2


def test_append_only_accumulates(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    AuditLog(path).log_request("https://a.test/", "GET", "pass")
    AuditLog(path).log_request("https://b.test/", "GET", "pass")  # reopened instance

    assert len(AuditLog(path).read_all()) == 2


def test_rotation_caps_live_file_and_keeps_backups(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, max_bytes=300, keep_backups=2)
    for index in range(50):
        log.log_request(f"https://a.test/{index}", "GET", "pass")

    assert path.exists()
    assert path.stat().st_size < 300 * 4  # bounded, not unbounded growth
    assert (tmp_path / "audit.jsonl.1").exists()
    assert not (tmp_path / "audit.jsonl.3").exists()  # only keep_backups=2 retained


def test_entries_are_single_line_json(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.log_request("https://api.example.com/a", "GET", "pass")

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["url"] == "https://api.example.com/a"
