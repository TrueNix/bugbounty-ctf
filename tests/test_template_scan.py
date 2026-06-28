"""Tests for template-driven discovery (nuclei wrapper + CVE correlation)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

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
        # ensure_nuclei returns None (offline / not installable) → graceful no-op,
        # never a real download during tests.
        monkeypatch.setattr(template_scan, "ensure_nuclei", lambda **k: None)
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
        monkeypatch.setattr(template_scan, "ensure_nuclei", lambda **k: "/usr/bin/nuclei")

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
        findings = nuclei_scan("http://t/", update_templates=False)
        assert findings and findings[0].template_id == "tech-detect"

    def test_ensure_nuclei_downloads(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        import io
        import zipfile

        monkeypatch.setattr(template_scan, "_BIN_DIR", str(tmp_path))
        monkeypatch.setattr(template_scan.shutil, "which", lambda _: None)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("nuclei", b"#!/bin/sh\necho fake\n")
        zip_bytes = buf.getvalue()

        class _R:
            def __init__(self, *, j: Any = None, c: bytes = b"") -> None:
                self._j, self.content = j, c

            def json(self) -> Any:
                return self._j

        def fetcher(url: str, **k: Any) -> Any:
            if url.endswith("releases/latest"):
                return _R(
                    j={
                        "assets": [
                            {
                                "name": "nuclei_3.0_linux_amd64.zip",
                                "browser_download_url": "http://x/nuclei.zip",
                            }
                        ]
                    }
                )
            return _R(c=zip_bytes)

        monkeypatch.setattr("platform.system", lambda: "Linux")
        monkeypatch.setattr("platform.machine", lambda: "x86_64")
        path = template_scan.ensure_nuclei(fetcher=fetcher)
        assert path == str(tmp_path / "nuclei")
        assert (tmp_path / "nuclei").exists()


class _Resp2:
    def __init__(self, status: int = 200, text: str = "") -> None:
        self.status_code = status
        self.text = text


class TestBundledData:
    def test_default_cve_db_loads_bundle(self) -> None:
        from bugbounty_ctf.template_scan import default_cve_db

        db = default_cve_db()
        assert "roundcube" in db and not any(k.startswith("_") for k in db)
        assert len(db) >= 10  # self-contained seed

    def test_load_templates_bundle(self) -> None:
        from bugbounty_ctf.template_scan import load_templates

        tpls = load_templates()
        ids = {t["id"] for t in tpls}
        assert "exposed-git-config" in ids


class TestBuiltinTemplateScan:
    def test_matches_git_config(self) -> None:
        from bugbounty_ctf.template_scan import builtin_template_scan

        sc = SecurityScanner("http://t.test/", db=ScannerDB(":memory:"))

        def fake(method: str, url: str, **kw: Any) -> _Resp2:
            if url.endswith("/.git/config"):
                return _Resp2(200, "[core]\nrepositoryformatversion = 0\n")
            return _Resp2(404, "nope")

        sc._make_request = fake  # type: ignore[method-assign]
        hits = builtin_template_scan("http://t.test/", scanner=sc, workers=4)
        assert any(h.template_id == "exposed-git-config" for h in hits)
        assert any(f["type"] == "template:exposed-git-config" for f in sc.findings)

    def test_no_match_on_catch_all(self) -> None:
        from bugbounty_ctf.template_scan import builtin_template_scan

        sc = SecurityScanner("http://t.test/", db=ScannerDB(":memory:"))
        sc._make_request = lambda *a, **k: _Resp2(200, "generic homepage")  # type: ignore[method-assign]
        assert builtin_template_scan("http://t.test/", scanner=sc, workers=4) == []


class TestNvdOnlineFeed:
    _NVD: ClassVar[dict[str, Any]] = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0009",
                    "descriptions": [{"lang": "en", "value": "Example remote bug"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [{"versionEndExcluding": "2.0"}]}]}],
                }
            }
        ]
    }

    def test_parse_nvd(self) -> None:
        from bugbounty_ctf.template_scan import _parse_nvd

        entries = _parse_nvd(self._NVD)
        assert entries == [
            {
                "cve": "CVE-2099-0009",
                "affected": "<2.0",
                "severity": "high",
                "name": "Example remote bug",
            }
        ]

    def test_update_cve_db_fetches_and_caches(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from bugbounty_ctf import template_scan

        monkeypatch.setattr(template_scan, "_CACHE_DIR", str(tmp_path))
        nvd = self._NVD

        def fetcher(url: str, **kw: Any) -> Any:
            return type("R", (), {"json": lambda self: nvd})()

        entries = template_scan.update_cve_db("acme", refresh=True, fetcher=fetcher)
        assert entries[0]["cve"] == "CVE-2099-0009"
        assert (tmp_path / "acme.json").exists()  # cached for subsequent runs

    def test_correlate_online_merges(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from bugbounty_ctf import template_scan

        monkeypatch.setattr(
            template_scan,
            "update_cve_db",
            lambda product, **k: (
                [{"cve": "CVE-2099-1", "affected": "<2.0", "severity": "high"}]
                if product == "acme"
                else []
            ),
        )
        matches = template_scan.correlate_cves([{"product": "acme", "version": "1.0"}], online=True)
        assert any(m["cve"] == "CVE-2099-1" for m in matches)
