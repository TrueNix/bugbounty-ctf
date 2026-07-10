"""Regression tests for SecurityScanner's ScannerDB target identity."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import requests

from bugbounty_ctf.engine import ScannerDB, SecurityScanner


def _response(text: str = "unchanged") -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response._content = text.encode()
    response.headers["Content-Type"] = "text/plain"
    response.response_time = 0.01
    return response


def _scanner(
    tmp_path: Path,
    db_path: Path,
    name: str,
    base_url: str,
    *,
    headers: dict[str, str] | None = None,
) -> SecurityScanner:
    return SecurityScanner(
        base_url,
        state_file=str(tmp_path / f"{name}.json"),
        db=ScannerDB(str(db_path)),
        headers=headers,
    )


def _record_history(scanner: SecurityScanner, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_request(*_args: Any, **_kwargs: Any) -> requests.Response:
        return _response()

    monkeypatch.setattr(scanner, "_make_request", fake_request)
    scanner.run_payload_set(
        _response(),
        "GET",
        f"{scanner.base_url}/probe",
        {"history-probe": "1"},
    )


def test_scanner_db_identity_isolates_same_ip_different_ports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: one scanner has persisted finding and history state for an IP:port.
    db_path = tmp_path / "scanner.db"
    scanner_a = _scanner(tmp_path, db_path, "a", "http://10.1.2.3:8080")
    scanner_a._record_finding(
        "/admin",
        "GET",
        "auth-bypass",
        ["auth_bypass"],
        ["admin loaded"],
        "auth_bypass",
    )
    _record_history(scanner_a, monkeypatch)

    # When: another scanner targets the same IP on a different network port.
    scanner_b = _scanner(tmp_path, db_path, "b", "http://10.1.2.3:9090")

    # Then: host stays plain for output/network use, but persisted state is isolated.
    assert scanner_a.host == "10.1.2.3"
    assert scanner_b.host == "10.1.2.3"
    assert scanner_b.findings == []
    assert scanner_b.db.query_history("target_host = ?", (scanner_b.target_identity,)) == []


def test_scanner_db_identity_isolates_same_host_port_different_schemes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: one scheme has persisted finding and history state for a host:port.
    db_path = tmp_path / "scanner.db"
    scanner_a = _scanner(tmp_path, db_path, "a", "http://10.1.2.3:8443")
    scanner_a._record_finding(
        "/admin",
        "GET",
        "auth-bypass",
        ["auth_bypass"],
        ["admin loaded"],
        "auth_bypass",
    )
    _record_history(scanner_a, monkeypatch)

    # When: another scanner targets the same host:port over a different scheme.
    scanner_b = _scanner(tmp_path, db_path, "b", "https://10.1.2.3:8443")

    # Then: plain host output stays stable, but persisted state is scheme-isolated.
    assert scanner_a.host == "10.1.2.3"
    assert scanner_b.host == "10.1.2.3"
    assert scanner_a.target_identity != scanner_b.target_identity
    assert scanner_b.findings == []
    assert scanner_b.db.query_history("target_host = ?", (scanner_b.target_identity,)) == []


def test_scanner_db_identity_isolates_same_ip_port_different_host_headers(
    tmp_path: Path,
) -> None:
    # Given: a virtual host on an IP:port has a persisted finding.
    db_path = tmp_path / "scanner.db"
    scanner_a = _scanner(
        tmp_path,
        db_path,
        "a",
        "http://10.1.2.3:8080",
        headers={"Host": "App.One:8080"},
    )
    scanner_a._record_finding(
        "/admin",
        "GET",
        "auth-bypass",
        ["auth_bypass"],
        ["admin loaded"],
        "auth_bypass",
    )

    # When: another scanner targets the same IP:port with a different vhost.
    scanner_b = _scanner(
        tmp_path,
        db_path,
        "b",
        "http://10.1.2.3:8080",
        headers={"host": "app.two:8080"},
    )

    # Then: vhost-specific findings do not bleed across.
    assert scanner_b.host == "10.1.2.3"
    assert scanner_b.findings == []


def test_scanner_db_identity_reloads_exact_same_target_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a scanner persisted state for an IP:port and Host header context.
    db_path = tmp_path / "scanner.db"
    scanner_a = _scanner(
        tmp_path,
        db_path,
        "a",
        "http://10.1.2.3:8080",
        headers={"Host": "App.One:8080"},
    )
    scanner_a._record_finding("/login", "POST", "' OR 1=1--", ["sqli"], ["err"], "sqli")
    _record_history(scanner_a, monkeypatch)

    # When: a new scanner uses the same normalized target identity.
    scanner_b = _scanner(
        tmp_path,
        db_path,
        "b",
        "http://10.1.2.3:8080",
        headers={"host": "app.one:8080"},
    )

    # Then: that exact context reloads its own persisted state.
    assert len(scanner_b.findings) == 1
    assert scanner_b.findings[0]["type"] == "sqli"
    assert len(scanner_b.db.query_history("target_host = ?", (scanner_b.target_identity,))) == 1


def test_scanner_db_identity_uses_only_nonsecret_target_fields(tmp_path: Path) -> None:
    # Given: URL/user headers contain sensitive and irrelevant values.
    db_path = tmp_path / "scanner.db"
    scanner = _scanner(
        tmp_path,
        db_path,
        "scanner",
        "https://user:pass@10.1.2.3:8443/path?token=url-secret#frag",
        headers={
            "Host": "VHOST.local:9443",
            "Authorization": "Bearer authorization-secret",
            "Cookie": "session=cookie-secret",
            "X-Api-Key": "x-api-secret",
        },
    )

    # When: SecurityScanner persists target-scoped state.
    scanner._record_finding("/admin", "GET", "payload", ["indicator"], ["detail"], "auth")

    # Then: the DB key contains only normalized target identity fields.
    target_id = scanner.db.query_findings()[0]["target_host"]
    assert target_id == "scheme=https;host=10.1.2.3;port=8443;vhost=vhost.local:9443"
    for secret in (
        "user",
        "pass",
        "/path",
        "url-secret",
        "authorization-secret",
        "cookie-secret",
        "x-api-secret",
    ):
        assert secret not in target_id
