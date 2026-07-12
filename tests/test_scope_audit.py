"""Engine integration: scope decisions are recorded to the audit log."""

from __future__ import annotations

from pathlib import Path

import pytest

from bugbounty_ctf import AuditLog, ScopeGuard, SecurityScanner
from bugbounty_ctf.scope import OutOfScopeError


def _scanner(tmp_path: Path, scope: ScopeGuard | None) -> SecurityScanner:
    return SecurityScanner(
        "https://app.example.com/",
        scope=scope,
        audit_log=AuditLog(tmp_path / "audit.jsonl"),
    )


def test_in_scope_request_records_pass(tmp_path: Path) -> None:
    scanner = _scanner(tmp_path, ScopeGuard(["*.example.com"]))

    scanner._scope_check("GET", "https://api.example.com/users")

    assert scanner.audit_log is not None
    assert scanner.audit_log.summary().passed == 1


def test_out_of_scope_records_fail_and_still_raises(tmp_path: Path) -> None:
    scanner = _scanner(tmp_path, ScopeGuard(["*.example.com"]))

    with pytest.raises(OutOfScopeError):
        scanner._scope_check("POST", "https://evil.test/x")

    assert scanner.audit_log is not None
    summary = scanner.audit_log.summary()
    assert summary.failed == 1
    assert summary.out_of_scope_hosts == ("evil.test",)


def test_no_scope_records_skip(tmp_path: Path) -> None:
    scanner = _scanner(tmp_path, None)

    scanner._scope_check("GET", "https://anything.test/")

    assert scanner.audit_log is not None
    assert scanner.audit_log.summary().skipped == 1


def test_wiring_is_inert_without_audit_log(tmp_path: Path) -> None:
    # Behaviour preserved: no audit log attached, out-of-scope still hard-stops.
    scanner = SecurityScanner("https://app.example.com/", scope=ScopeGuard(["*.example.com"]))

    with pytest.raises(OutOfScopeError):
        scanner._scope_check("GET", "https://evil.test/")
    assert scanner.audit_log is None
