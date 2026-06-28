"""Template-driven discovery — the open equivalent of a Nessus plugin feed.

Two complementary, opt-in capabilities:

1. ``nuclei_scan`` — shell out to the ``nuclei`` engine (permissively-licensed,
   community-maintained YAML templates) and fold its results into the findings
   DB / second brain. No proprietary plugins are bundled; if ``nuclei`` is not
   installed it degrades gracefully.

2. ``correlate_cves`` — the "stop trusting the version banner" fix: map the
   service/version fingerprints we already collect to known CVEs via a
   data-driven feed (load a JSON dataset, or query NVD online). The matching is
   generic; the CVE data is external, never hardcoded per target.

Usage:
    from bugbounty_ctf.template_scan import nuclei_scan, correlate_cves

    findings = nuclei_scan("http://target/", scanner=scanner, severity="high,critical")
    cves = correlate_cves([{"product": "roundcube", "version": "1.6.10"}])
"""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

# A tiny, factual seed so the correlator is useful out of the box. Production
# use should load a full NVD/Vulners feed via load_cve_db() or online=True.
_SEED_CVE_DB: dict[str, list[dict[str, str]]] = {
    "roundcube": [
        {"cve": "CVE-2025-49113", "affected": "<=1.6.10", "severity": "critical"},
    ],
}


@dataclass
class TemplateFinding:
    """One result from a template engine (nuclei) or a CVE correlation."""

    template_id: str
    name: str
    severity: str = "info"
    matched_at: str = ""
    tags: list[str] = field(default_factory=list)
    source: str = "nuclei"

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "matched_at": self.matched_at,
            "tags": self.tags,
            "source": self.source,
        }


def nuclei_available() -> bool:
    """True if the ``nuclei`` binary is on PATH."""
    return shutil.which("nuclei") is not None


def nuclei_scan(
    target: str,
    *,
    scanner: Any | None = None,
    severity: str = "medium,high,critical",
    tags: str | None = None,
    extra_args: list[str] | None = None,
    timeout: int = 600,
) -> list[TemplateFinding]:
    """Run nuclei against ``target`` and return parsed findings.

    Records each finding into the scanner's second brain (provenance
    ``nuclei:<template-id>``) when a scanner is supplied. Returns an empty list
    (not an error) when nuclei is absent, so callers can always invoke it.
    """
    if not nuclei_available():
        print(
            "[*] nuclei not installed — skipping template scan (pip/go install projectdiscovery/nuclei)"
        )
        return []

    cmd = ["nuclei", "-silent", "-jsonl", "-severity", severity, "-u", target]
    if tags:
        cmd += ["-tags", tags]
    if extra_args:
        cmd += extra_args

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"[-] nuclei timed out after {timeout}s")
        return []
    except OSError as e:
        print(f"[-] nuclei failed to launch: {e}")
        return []

    return _parse_nuclei(result.stdout, scanner=scanner)


def _parse_nuclei(stdout: str, *, scanner: Any | None = None) -> list[TemplateFinding]:
    findings: list[TemplateFinding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(obj, dict):
            continue
        info = obj.get("info", {}) or {}
        tid = str(obj.get("template-id") or obj.get("templateID") or "unknown")
        finding = TemplateFinding(
            template_id=tid,
            name=str(info.get("name") or tid),
            severity=str(info.get("severity") or "info"),
            matched_at=str(obj.get("matched-at") or obj.get("host") or ""),
            tags=[str(t) for t in (info.get("tags") or [])],
            source="nuclei",
        )
        findings.append(finding)
        if scanner is not None:
            with contextlib.suppress(Exception):
                scanner._record_finding(
                    endpoint=finding.matched_at,
                    method="",
                    payload=finding.template_id,
                    indicators=["nuclei", finding.severity],
                    details=[finding.name],
                    vuln_type=f"nuclei:{finding.template_id}",
                    source=f"nuclei:{finding.template_id}",
                )
    print(f"[*] nuclei: {len(findings)} finding(s)")
    return findings


# ---------------------------------------------------------------- CVE correlation
def _parse_version(v: str) -> tuple[int, ...]:
    nums: list[int] = []
    for part in v.strip().split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        nums.append(int(digits) if digits else 0)
    return tuple(nums)


def _cmp(a: str, b: str) -> int:
    va, vb = _parse_version(a), _parse_version(b)
    width = max(len(va), len(vb))
    va += (0,) * (width - len(va))
    vb += (0,) * (width - len(vb))
    return (va > vb) - (va < vb)


def version_matches(version: str, spec: str) -> bool:
    """Test a version against a spec: ``<=x`` ``<x`` ``>=x`` ``>x`` ``==x`` ``a-b`` or ``*``."""
    spec = spec.strip()
    if spec in ("", "*"):
        return True
    if "-" in spec and spec[0] not in "<>=":
        lo, hi = (s.strip() for s in spec.split("-", 1))
        return _cmp(version, lo) >= 0 and _cmp(version, hi) <= 0
    for op in ("<=", ">=", "==", "<", ">"):
        if spec.startswith(op):
            target = spec[len(op) :].strip()
            c = _cmp(version, target)
            return {
                "<=": c <= 0,
                ">=": c >= 0,
                "==": c == 0,
                "<": c < 0,
                ">": c > 0,
            }[op]
    return _cmp(version, spec) == 0


def load_cve_db(path: str) -> dict[str, list[dict[str, str]]]:
    """Load a CVE dataset: ``{product: [{cve, affected, severity}, ...]}``."""
    with open(path) as f:
        data: dict[str, list[dict[str, str]]] = json.load(f)
    return data


def correlate_cves(
    fingerprints: list[dict[str, str]],
    *,
    cve_db: dict[str, list[dict[str, str]]] | None = None,
    scanner: Any | None = None,
) -> list[dict[str, Any]]:
    """Map ``[{product, version}]`` fingerprints to known CVEs from a feed.

    Uses ``cve_db`` (or a tiny factual seed) — never per-target hardcoding. This
    is the systematic "verify the version against known CVEs" step instead of
    trusting a banner.
    """
    db = cve_db or _SEED_CVE_DB
    matches: list[dict[str, Any]] = []
    for fp in fingerprints:
        product = (fp.get("product") or "").lower()
        version = fp.get("version") or ""
        if not product or not version:
            continue
        for entry in db.get(product, []):
            if version_matches(version, entry.get("affected", "*")):
                match = {
                    "product": product,
                    "version": version,
                    "cve": entry.get("cve", ""),
                    "severity": entry.get("severity", "unknown"),
                    "affected": entry.get("affected", "*"),
                }
                matches.append(match)
                if scanner is not None:
                    with contextlib.suppress(Exception):
                        scanner._record_finding(
                            endpoint=scanner.base_url,
                            method="",
                            payload=f"{product} {version}",
                            indicators=["cve", match["severity"]],
                            details=[f"{match['cve']} affects {product} {entry.get('affected')}"],
                            vuln_type=f"cve:{match['cve']}",
                            source="correlate_cves",
                        )
    return matches
