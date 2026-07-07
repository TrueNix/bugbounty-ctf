from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from scripts.refresh_cve_db import RefreshOptions, refresh_cve_db


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


def _nvd_payload(cve_id: str, *, affected: str, severity: str, name: str) -> dict[str, Any]:
    upper_severity = severity.upper()
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseSeverity": upper_severity}},
                        ],
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "versionEndExcluding": affected.removeprefix("<"),
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                    "descriptions": [{"lang": "en", "value": name}],
                },
            },
        ],
    }


def _write_db(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n")


def _options(db_path: Path, fetcher: Callable[..., _FakeResponse]) -> RefreshOptions:
    return RefreshOptions(
        db_path=db_path,
        fetcher=fetcher,
        sleeper=lambda seconds: None,
        extra_products=(),
    )


def test_merge_preserves_comment_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from bugbounty_ctf import template_scan

    # Given: a bundled database with metadata and one tracked product.
    monkeypatch.setattr(template_scan, "_CACHE_DIR", str(tmp_path / "cache"))
    db_path = tmp_path / "cve_db.json"
    _write_db(
        db_path,
        {
            "_comment": "keep me",
            "acme": [
                {
                    "cve": "CVE-2099-0001",
                    "affected": "<1.0",
                    "severity": "medium",
                    "name": "Existing bug",
                },
            ],
        },
    )

    def fetcher(url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            _nvd_payload(
                "CVE-2099-0002",
                affected="<2.0",
                severity="high",
                name="Fresh bug",
            )
        )

    # When: the refresh runs through the injected NVD fetcher.
    summary = refresh_cve_db(_options(db_path, fetcher))

    # Then: metadata is still present and new CVEs are merged.
    refreshed = json.loads(db_path.read_text())
    assert refreshed["_comment"] == "keep me"
    assert [entry["cve"] for entry in refreshed["acme"]] == [
        "CVE-2099-0001",
        "CVE-2099-0002",
    ]
    assert summary.products_updated == 1
    assert summary.net_new_cves == 1


def test_output_is_sorted_and_stable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from bugbounty_ctf import template_scan

    # Given: unsorted products and an unsorted fetched CVE id.
    monkeypatch.setattr(template_scan, "_CACHE_DIR", str(tmp_path / "cache"))
    db_path = tmp_path / "cve_db.json"
    _write_db(
        db_path,
        {
            "_comment": "stable",
            "zeta": [
                {"severity": "low", "name": "Zeta", "affected": "*", "cve": "CVE-2099-0009"},
            ],
            "acme": [
                {"severity": "low", "name": "Acme", "affected": "*", "cve": "CVE-2099-0003"},
            ],
        },
    )

    def fetcher(url: str, **kwargs: Any) -> _FakeResponse:
        product = kwargs["params"]["keywordSearch"]
        if product == "acme":
            return _FakeResponse(
                _nvd_payload(
                    "CVE-2099-0001",
                    affected="<2.0",
                    severity="critical",
                    name="Acme first",
                )
            )
        return _FakeResponse({"vulnerabilities": []})

    # When: the refresh runs twice with the same upstream responses.
    options = _options(db_path, fetcher)
    first_summary = refresh_cve_db(options)
    first_bytes = db_path.read_bytes()
    second_summary = refresh_cve_db(options)
    second_bytes = db_path.read_bytes()

    # Then: product keys and CVE entries are sorted, and reruns are byte-stable.
    refreshed = json.loads(first_bytes)
    assert list(refreshed) == ["_comment", "acme", "zeta"]
    assert [entry["cve"] for entry in refreshed["acme"]] == [
        "CVE-2099-0001",
        "CVE-2099-0003",
    ]
    assert first_bytes == second_bytes
    assert first_summary.net_new_cves == 1
    assert second_summary.net_new_cves == 0


def test_new_cves_added_existing_updated_not_duplicated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from bugbounty_ctf import template_scan

    # Given: an existing CVE that upstream now reports with a corrected severity.
    monkeypatch.setattr(template_scan, "_CACHE_DIR", str(tmp_path / "cache"))
    db_path = tmp_path / "cve_db.json"
    _write_db(
        db_path,
        {
            "_comment": "update",
            "acme": [
                {
                    "cve": "CVE-2099-0001",
                    "affected": "<1.0",
                    "severity": "medium",
                    "name": "Old name",
                },
            ],
        },
    )

    def fetcher(url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            _nvd_payload(
                "CVE-2099-0001",
                affected="<2.0",
                severity="critical",
                name="Corrected upstream name",
            )
        )

    # When: the refresh merges upstream data by CVE id.
    summary = refresh_cve_db(_options(db_path, fetcher))

    # Then: the CVE is updated in place instead of duplicated.
    entries = json.loads(db_path.read_text())["acme"]
    assert entries == [
        {
            "cve": "CVE-2099-0001",
            "affected": "<2.0",
            "severity": "critical",
            "name": "Corrected upstream name",
        },
    ]
    assert summary.total_cves == 1
    assert summary.net_new_cves == 0


def test_runs_offline_without_api_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from bugbounty_ctf import template_scan

    # Given: NVD is unavailable and the product only exists in the local file.
    monkeypatch.setattr(template_scan, "_CACHE_DIR", str(tmp_path / "cache"))
    db_path = tmp_path / "cve_db.json"
    original = {
        "_comment": "offline",
        "acme": [
            {
                "cve": "CVE-2099-0001",
                "affected": "<1.0",
                "severity": "medium",
                "name": "Keep local entry",
            },
        ],
    }
    _write_db(db_path, original)

    def fetcher(url: str, **kwargs: Any) -> _FakeResponse:
        raise OSError("network unavailable")

    # When: the refresh runs without an API key.
    summary = refresh_cve_db(_options(db_path, fetcher))

    # Then: existing local data is preserved and no network failure escapes.
    assert json.loads(db_path.read_text()) == original
    assert summary.products_updated == 0
    assert summary.total_cves == 1
