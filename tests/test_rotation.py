"""Tests for bounded-growth primitives: JSONL rotation and file retention."""

from __future__ import annotations

import os
from pathlib import Path

from bugbounty_ctf.audit_log import AuditLog
from bugbounty_ctf.rotation import prune_files, rotate_jsonl


def test_rotate_jsonl_rotates_when_oversized(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_text("x" * 200, encoding="utf-8")

    assert rotate_jsonl(path, max_bytes=100, keep=3) is True
    assert (tmp_path / "log.jsonl.1").exists()
    assert not path.exists()  # live file moved to .1


def test_rotate_jsonl_noop_when_small(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    path.write_text("tiny", encoding="utf-8")

    assert rotate_jsonl(path, max_bytes=1_000, keep=3) is False
    assert not (tmp_path / "log.jsonl.1").exists()


def test_rotate_jsonl_missing_file_is_noop(tmp_path: Path) -> None:
    assert rotate_jsonl(tmp_path / "absent.jsonl", max_bytes=1) is False


def test_rotate_jsonl_keeps_only_n_backups(tmp_path: Path) -> None:
    path = tmp_path / "log.jsonl"
    for _ in range(5):
        path.write_text("x" * 200, encoding="utf-8")  # recreate the live file each round
        rotate_jsonl(path, max_bytes=100, keep=2)

    assert (tmp_path / "log.jsonl.1").exists()
    assert (tmp_path / "log.jsonl.2").exists()
    assert not (tmp_path / "log.jsonl.3").exists()


def test_prune_files_keeps_newest(tmp_path: Path) -> None:
    for index in range(5):
        entry = tmp_path / f"report_{index}.md"
        entry.write_text("x", encoding="utf-8")
        os.utime(entry, (index, index))  # deterministic, increasing mtimes

    removed = prune_files(tmp_path, "report_*", keep=2)

    assert {p.name for p in removed} == {"report_0.md", "report_1.md", "report_2.md"}
    assert (tmp_path / "report_3.md").exists()
    assert (tmp_path / "report_4.md").exists()


def test_prune_files_only_touches_matching_pattern(tmp_path: Path) -> None:
    (tmp_path / "report_old.md").write_text("x", encoding="utf-8")
    (tmp_path / "keepme.txt").write_text("x", encoding="utf-8")

    prune_files(tmp_path, "report_*", keep=0)

    assert not (tmp_path / "report_old.md").exists()
    assert (tmp_path / "keepme.txt").exists()  # non-matching file untouched


def test_prune_files_missing_dir_is_noop(tmp_path: Path) -> None:
    assert prune_files(tmp_path / "nope", "report_*", keep=1) == []


def test_audit_log_still_rotates_via_shared_helper(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, max_bytes=300, keep_backups=2)
    for index in range(50):
        log.log_request(f"https://a.test/{index}", "GET", "pass")

    assert path.exists()
    assert path.stat().st_size < 300 * 4  # bounded, not unbounded growth
    assert (tmp_path / "audit.jsonl.1").exists()
