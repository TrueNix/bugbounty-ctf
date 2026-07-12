"""Scope-compliance audit trail — record every request's scope decision.

A :class:`ScopeGuard` decides whether a request is in scope; it does not
remember its decisions. On a real engagement you often need to *prove*, after
the fact, that every request stayed inside the authorized allowlist. This module
is that record: an append-only JSONL log where each line captures one request's
URL, method, and scope-check outcome (``pass`` / ``fail`` / ``skip``), with a
timestamp and an optional session identity for correlation.

It is deliberately independent of what the request found — it is an
accountability log, not engagement memory. It carries no findings, payloads, or
secrets, only the scope decision. The file is append-only, rotated by size, and
written under an exclusive lock so concurrent scanners cannot interleave lines.

Usage:
    from bugbounty_ctf.audit_log import AuditLog

    audit = AuditLog()  # ~/.hermes/audit.jsonl
    audit.log_request("https://api.example.com/x", "GET", "pass", response_status=200)
    print(audit.summary())  # AuditSummary(total=1, passed=1, ...)
"""

from __future__ import annotations

import fcntl
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

SCHEMA_VERSION = 1
DEFAULT_PATH = Path("~/.hermes/audit.jsonl")
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_KEEP = 3

VALID_METHODS = frozenset(
    {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
)
VALID_SCOPE_CHECKS = frozenset({"pass", "fail", "skip"})

_REQUIRED = {"ts", "url", "method", "scope_check", "schema_version"}
_OPTIONAL = {"response_status", "finding_id", "session_id", "error"}
_ALL = _REQUIRED | _OPTIONAL


class AuditError(ValueError):
    """Raised when an audit entry is malformed."""


@dataclass(frozen=True, slots=True)
class AuditSummary:
    """Post-engagement rollup of the scope-compliance log."""

    total: int
    passed: int
    failed: int
    skipped: int
    out_of_scope_hosts: tuple[str, ...]

    @property
    def clean(self) -> bool:
        """True if no request was recorded as out of scope."""
        return self.failed == 0


class AuditLog:
    """Append-only, size-rotated scope-compliance audit trail."""

    def __init__(
        self,
        path: str | Path = DEFAULT_PATH,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        keep_backups: int = DEFAULT_KEEP,
        session_id: str | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.keep_backups = keep_backups
        self.session_id = session_id or os.environ.get("HERMES_SESSION_ID") or None

    def log_request(
        self,
        url: str,
        method: str,
        scope_check: str,
        *,
        response_status: int | None = None,
        finding_id: str | None = None,
        error: str | None = None,
    ) -> dict[str, object]:
        """Validate and append one request's scope decision. Returns the entry."""
        entry = self._build(
            url=url,
            method=method,
            scope_check=scope_check,
            response_status=response_status,
            finding_id=finding_id,
            error=error,
        )
        self._append(entry)
        return entry

    def read_all(self) -> list[dict[str, object]]:
        """Return every recorded entry; corrupted lines are skipped with a warning."""
        if not self.path.exists():
            return []
        entries: list[dict[str, object]] = []
        with self.path.open(encoding="utf-8") as handle:
            for lineno, raw in enumerate(handle, start=1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    decoded = json.loads(line)
                except json.JSONDecodeError as exc:
                    print(
                        f"WARNING: audit line {lineno} is corrupted (skipping): {exc}",
                        file=sys.stderr,
                    )
                    continue
                if isinstance(decoded, dict):
                    entries.append(decoded)
        return entries

    def summary(self) -> AuditSummary:
        """Roll up recorded entries for post-engagement review."""
        passed = failed = skipped = 0
        out_of_scope: list[str] = []
        for entry in self.read_all():
            check = entry.get("scope_check")
            if check == "pass":
                passed += 1
            elif check == "fail":
                failed += 1
                host = urlparse(str(entry.get("url", ""))).hostname
                if host:
                    out_of_scope.append(host)
            elif check == "skip":
                skipped += 1
        return AuditSummary(
            total=passed + failed + skipped,
            passed=passed,
            failed=failed,
            skipped=skipped,
            out_of_scope_hosts=tuple(sorted(set(out_of_scope))),
        )

    def _build(
        self,
        *,
        url: str,
        method: str,
        scope_check: str,
        response_status: int | None,
        finding_id: str | None,
        error: str | None,
    ) -> dict[str, object]:
        if not isinstance(url, str) or not url.strip():
            raise AuditError("url must be a non-empty string")
        normalized_method = method.upper() if isinstance(method, str) else ""
        if normalized_method not in VALID_METHODS:
            raise AuditError(f"method must be one of {sorted(VALID_METHODS)}, got {method!r}")
        if scope_check not in VALID_SCOPE_CHECKS:
            raise AuditError(
                f"scope_check must be one of {sorted(VALID_SCOPE_CHECKS)}, got {scope_check!r}"
            )
        if response_status is not None and not isinstance(response_status, int):
            raise AuditError("response_status must be an integer or None")

        entry: dict[str, object] = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "url": url,
            "method": normalized_method,
            "scope_check": scope_check,
            "schema_version": SCHEMA_VERSION,
        }
        if response_status is not None:
            entry["response_status"] = response_status
        if finding_id is not None:
            entry["finding_id"] = finding_id
        if error is not None:
            entry["error"] = error
        if self.session_id is not None:
            entry["session_id"] = self.session_id
        return entry

    def _append(self, entry: dict[str, object]) -> None:
        line = (json.dumps(entry, separators=(",", ":")) + "\n").encode("utf-8")
        self._rotate_if_needed()
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                written = os.write(fd, line)
                if written != len(line):
                    raise OSError(f"partial audit write: {written}/{len(line)} bytes")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _rotate_if_needed(self) -> bool:
        try:
            oversized = self.path.stat().st_size >= self.max_bytes
        except FileNotFoundError:
            return False
        if not oversized:
            return False
        fd = os.open(str(self.path), os.O_RDONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                if self.path.stat().st_size < self.max_bytes:
                    return False  # another process rotated first
            except FileNotFoundError:
                return False
            self._rotate()
            return True
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _rotate(self) -> None:
        oldest = self.path.with_suffix(self.path.suffix + f".{self.keep_backups}")
        if oldest.exists():
            oldest.unlink()
        for index in range(self.keep_backups - 1, 0, -1):
            src = self.path.with_suffix(self.path.suffix + f".{index}")
            dst = self.path.with_suffix(self.path.suffix + f".{index + 1}")
            if src.exists():
                os.replace(str(src), str(dst))
        os.replace(str(self.path), str(self.path.with_suffix(self.path.suffix + ".1")))
