from __future__ import annotations

import json
import os
import sqlite3
import stat
from pathlib import Path

import pytest

import bugbounty_ctf.engine as engine
from bugbounty_ctf.engine import ScannerDB, SecurityScanner


def _scanner(
    tmp_path: Path,
    db_path: Path,
    name: str,
    base_url: str = "http://10.1.2.3:8080",
    *,
    headers: dict[str, str] | None = None,
) -> SecurityScanner:
    return SecurityScanner(
        base_url,
        state_file=str(tmp_path / f"{name}.json"),
        db=ScannerDB(str(db_path)),
        headers=headers,
    )


def test_auth_material_reloads_for_same_target_without_printing_secrets(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given: a scanner captures credentials, a token, and a cookie for one target identity.
    db_path = tmp_path / "scanner.db"
    scanner = _scanner(
        tmp_path,
        db_path,
        "writer",
        headers={"Host": "App.One:8080"},
    )

    # When: the auth material is captured and a fresh scanner opens the same DB/target.
    scanner.capture_credential("admin", "password-secret", source="login-form")
    scanner.capture_token("jwt", "token-secret", source="login-api")
    scanner.capture_cookie("sid", "cookie-secret")
    capture_output = capsys.readouterr().out
    reloaded = _scanner(
        tmp_path,
        db_path,
        "reader",
        headers={"host": "app.one:8080"},
    )
    reload_output = capsys.readouterr().out

    # Then: the new scanner has reusable auth state, including a live session cookie.
    assert reloaded.captured_credentials == [
        {"username": "admin", "password": "password-secret", "source": "login-form"}
    ]
    assert reloaded.captured_tokens == {"jwt": "token-secret"}
    assert reloaded.captured_cookies == {"sid": "cookie-secret"}
    assert reloaded.session.cookies.get("sid") == "cookie-secret"
    assert reload_output == ""
    for secret in ("password-secret", "token-secret", "cookie-secret"):
        assert secret not in capture_output
        assert secret not in reload_output


def test_auth_material_dedupes_exact_repeats_but_keeps_distinct_values(tmp_path: Path) -> None:
    # Given: one scanner captures exact repeats and same-name distinct values.
    db_path = tmp_path / "scanner.db"
    scanner = _scanner(tmp_path, db_path, "writer")

    # When: auth material is captured repeatedly.
    scanner.capture_credential("alice", "password-one", source="login")
    scanner.capture_credential("alice", "password-one", source="login")
    scanner.capture_credential("alice", "password-two", source="login")
    scanner.capture_token("api", "token-one", source="header")
    scanner.capture_token("api", "token-one", source="header")
    scanner.capture_token("api", "token-two", source="header")
    scanner.capture_token("api", "token-one", source="body")
    scanner.capture_cookie("sid", "cookie-one")
    scanner.capture_cookie("sid", "cookie-one")
    scanner.capture_cookie("sid", "cookie-two")

    # Then: the durable table dedupes only exact key repeats.
    rows = scanner.db.load_auth_material(scanner.target_identity)
    material = {(row["kind"], row["name"], row["value"], row["source"]) for row in rows}
    assert material == {
        ("credential", "alice", "password-one", "login"),
        ("credential", "alice", "password-two", "login"),
        ("token", "api", "token-one", "header"),
        ("token", "api", "token-two", "header"),
        ("token", "api", "token-one", "body"),
        ("cookie", "sid", "cookie-one", ""),
        ("cookie", "sid", "cookie-two", ""),
    }


def test_auth_material_is_isolated_by_port_and_host_header(tmp_path: Path) -> None:
    # Given: auth material is persisted for one IP:port and Host-header context.
    db_path = tmp_path / "scanner.db"
    scanner = _scanner(
        tmp_path,
        db_path,
        "writer",
        "http://10.1.2.3:8080",
        headers={"Host": "App.One:8080"},
    )
    scanner.capture_token("jwt", "target-token", source="login")
    scanner.capture_cookie("sid", "target-cookie")

    # When: scanners open the same DB with a different port, a different Host, and the same target.
    different_port = _scanner(
        tmp_path,
        db_path,
        "different-port",
        "http://10.1.2.3:9090",
        headers={"Host": "App.One:8080"},
    )
    different_host = _scanner(
        tmp_path,
        db_path,
        "different-host",
        "http://10.1.2.3:8080",
        headers={"Host": "App.Two:8080"},
    )
    same_target = _scanner(
        tmp_path,
        db_path,
        "same-target",
        "http://10.1.2.3:8080",
        headers={"host": "app.one:8080"},
    )

    # Then: auth material reloads only for the exact normalized target identity.
    assert different_port.captured_tokens == {}
    assert different_port.captured_cookies == {}
    assert different_port.session.cookies.get("sid") is None
    assert different_host.captured_tokens == {}
    assert different_host.captured_cookies == {}
    assert different_host.session.cookies.get("sid") is None
    assert same_target.captured_tokens == {"jwt": "target-token"}
    assert same_target.captured_cookies == {"sid": "target-cookie"}
    assert same_target.session.cookies.get("sid") == "target-cookie"


def test_save_snapshot_redacts_auth_material(tmp_path: Path) -> None:
    # Given: the scanner holds auth material that is intentionally persisted only in SQLite.
    db_path = tmp_path / "scanner.db"
    snapshot = tmp_path / "snapshot.json"
    scanner = SecurityScanner(
        "http://target.test/",
        state_file=str(snapshot),
        db=ScannerDB(str(db_path)),
    )
    scanner.capture_credential("admin", "password-secret", source="login")
    scanner.capture_token("jwt", "token-secret", source="header")
    scanner.capture_cookie("sid", "cookie-secret")

    # When: a human-readable JSON snapshot is written.
    scanner.save_snapshot()
    snapshot_text = snapshot.read_text()
    snapshot_data = json.loads(snapshot_text)

    # Then: no auth material or secret values are exposed in the artifact.
    assert "captured_credentials" not in snapshot_data
    assert "captured_tokens" not in snapshot_data
    assert "captured_cookies" not in snapshot_data
    for secret in ("password-secret", "token-secret", "cookie-secret"):
        assert secret not in snapshot_text


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
def test_scannerdb_creates_missing_db_owner_read_write_before_sqlite_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a ScannerDB is backed by a missing normal on-disk SQLite path.
    db_path = tmp_path / "scanner.db"
    real_connect = engine.sqlite3.connect
    observed_modes: list[int] = []

    def fake_connect(database: str, *_args: object, **_kwargs: object) -> sqlite3.Connection:
        observed_modes.append(stat.S_IMODE(db_path.stat().st_mode))
        assert database == str(db_path)
        return real_connect(":memory:")

    monkeypatch.setattr(engine.sqlite3, "connect", fake_connect)

    # When: SQLite opens the database.
    db = ScannerDB(str(db_path))
    db.close()

    # Then: the file already exists as 0600 before sqlite3.connect receives the path.
    assert observed_modes == [0o600]
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
def test_scannerdb_corrects_existing_permissive_db_before_sqlite_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: an existing DB file is readable by group/other.
    db_path = tmp_path / "scanner.db"
    db_path.write_bytes(b"")
    db_path.chmod(0o644)
    real_connect = engine.sqlite3.connect
    observed_modes: list[int] = []

    def fake_connect(database: str, *_args: object, **_kwargs: object) -> sqlite3.Connection:
        observed_modes.append(stat.S_IMODE(db_path.stat().st_mode))
        assert database == str(db_path)
        return real_connect(":memory:")

    monkeypatch.setattr(engine.sqlite3, "connect", fake_connect)

    # When: SQLite opens the database.
    db = ScannerDB(str(db_path))
    db.close()

    # Then: the permissive file is corrected before sqlite3.connect receives the path.
    assert observed_modes == [0o600]
    assert stat.S_IMODE(db_path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
def test_scannerdb_fails_closed_when_existing_db_fchmod_fails_without_leaking_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: an existing DB path includes secret-looking content and fchmod fails.
    db_path = tmp_path / "target-token-secret.db"
    db_path.write_bytes(b"")

    def fail_fchmod(fd: int, mode: int) -> None:
        raise OSError(f"cannot fchmod {fd} with token-secret")

    monkeypatch.setattr(engine.os, "fchmod", fail_fchmod)

    # When: ScannerDB tries to secure the database.
    with pytest.raises(engine.DatabaseSecurityError) as excinfo:
        ScannerDB(str(db_path))

    # Then: the operation fails closed with a generic safe error.
    error_text = str(excinfo.value)
    assert error_text == "Could not secure database file permissions"
    assert str(db_path) not in error_text
    assert "token-secret" not in error_text
    assert excinfo.value.__cause__ is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
def test_scannerdb_fails_closed_when_missing_db_create_fails_without_leaking_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a missing DB path includes secret-looking content and secure creation fails.
    db_path = tmp_path / "target-token-secret.db"

    def fail_open(path: str, flags: int, mode: int) -> int:
        raise OSError(f"cannot open {path} with token-secret")

    monkeypatch.setattr(engine.os, "open", fail_open)

    # When: ScannerDB tries to secure the database.
    with pytest.raises(engine.DatabaseSecurityError) as excinfo:
        ScannerDB(str(db_path))

    # Then: the operation fails closed with a generic safe error.
    error_text = str(excinfo.value)
    assert error_text == "Could not secure database file permissions"
    assert str(db_path) not in error_text
    assert "token-secret" not in error_text
    assert excinfo.value.__cause__ is None


@pytest.mark.skipif(
    os.name == "nt" or not hasattr(os, "O_NOFOLLOW"),
    reason="POSIX O_NOFOLLOW support required",
)
def test_scannerdb_rejects_symlink_db_path_before_sqlite_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given: a DB path is a symlink to another normal file.
    target_path = tmp_path / "real.db"
    target_path.write_bytes(b"")
    db_path = tmp_path / "scanner.db"
    db_path.symlink_to(target_path)

    def fail_connect(database: str, *_args: object, **_kwargs: object) -> sqlite3.Connection:
        pytest.fail(f"sqlite3.connect should not open symlink DB path: {database}")

    monkeypatch.setattr(engine.sqlite3, "connect", fail_connect)

    # When: ScannerDB tries to secure the database.
    with pytest.raises(engine.DatabaseSecurityError) as excinfo:
        ScannerDB(str(db_path))

    # Then: the symlink path fails closed without exposing path details.
    error_text = str(excinfo.value)
    assert error_text == "Could not secure database file permissions"
    assert str(db_path) not in error_text
    assert excinfo.value.__cause__ is None
