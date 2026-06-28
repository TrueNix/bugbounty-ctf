"""Tests for template-driven discovery (nuclei wrapper + CVE correlation)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from bugbounty_ctf import template_scan
from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.template_scan import (
    _parse_nuclei,
    correlate_cves,
    nuclei_scan,
    version_matches,
)


class TestVersionMatching:
    def test_operators(self) -> None:
        assert version_matches("1.6.10", "<=1.6.10")
        assert not version_matches("1.6.16", "<=1.6.10")
        assert version_matches("2.0", ">=1.9")
        assert version_matches("1.6.10", "==1.6.10")
        assert version_matches("1.5", "1.0-1.6")
        assert not version_matches("1.7", "1.0-1.6")
        assert version_matches("anything", "*")


class TestCorrelateCves:
    def test_seed_match_and_miss(self) -> None:
        hit = correlate_cves([{"product": "roundcube", "version": "1.6.10"}])
        assert hit and hit[0]["cve"] == "CVE-2025-49113"
        miss = correlate_cves([{"product": "roundcube", "version": "1.6.16"}])
        assert miss == []  # patched version is correctly NOT matched

    def test_custom_db_and_recording(self) -> None:
        db = {"acme": [{"cve": "CVE-2099-0001", "affected": "<2.0", "severity": "high"}]}
        sc = SecurityScanner("http://t.test/", db=ScannerDB(":memory:"))
        matches = correlate_cves([{"product": "acme", "version": "1.5"}], cve_db=db, scanner=sc)
        assert matches[0]["cve"] == "CVE-2099-0001"
        assert any(f["type"] == "cve:CVE-2099-0001" for f in sc.findings)


class TestNucleiWrapper:
    def test_graceful_when_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(template_scan, "nuclei_available", lambda: False)
        assert nuclei_scan("http://t/") == []

    def test_parses_jsonl_and_records(self) -> None:
        sc = SecurityScanner("http://t.test/", db=ScannerDB(":memory:"))
        out = "\n".join(
            json.dumps(o)
            for o in [
                {
                    "template-id": "CVE-2021-1234",
                    "info": {"name": "Example RCE", "severity": "critical", "tags": ["cve", "rce"]},
                    "matched-at": "http://t.test/x",
                },
                {"info": {"name": "Exposed panel", "severity": "low"}, "host": "http://t.test"},
                "not json",
            ]
        )
        findings = _parse_nuclei(out, scanner=sc)
        assert len(findings) == 2
        assert findings[0].template_id == "CVE-2021-1234" and findings[0].severity == "critical"
        assert any(f["source"] == "nuclei:CVE-2021-1234" for f in sc.findings)

    def test_scan_runs_when_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(template_scan, "nuclei_available", lambda: True)

        def fake_run(*a: Any, **k: Any) -> Any:
            import subprocess

            return subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps(
                    {"template-id": "tech-detect", "info": {"name": "nginx", "severity": "info"}}
                ),
                stderr="",
            )

        monkeypatch.setattr(template_scan.subprocess, "run", fake_run)
        findings = nuclei_scan("http://t/")
        assert findings and findings[0].template_id == "tech-detect"
