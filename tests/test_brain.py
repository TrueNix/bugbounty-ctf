from __future__ import annotations

import hashlib
import json
import sqlite3
import stat
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Final

import pytest
import requests

import bugbounty_ctf.brain as brain
from bugbounty_ctf.brain import (
    DATABASE_MAX_BYTES,
    HTTP_TIMEOUT,
    MANIFEST_MAX_BYTES,
    MANIFEST_URL,
    BrainError,
    BrainStore,
    _default_fetch,
    _validate_download_url,
)

DB_URL: Final = (
    "https://github.com/TrueNix/bugbounty-brain/releases/latest/download/reference_knowledge.db"
)
GENERATED_AT: Final = "2026-07-10T10:00:00Z"
SOURCE_SHA256: Final = "b" * 64


class FakeFetcher:
    def __init__(self, responses: dict[str, bytes]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, int, tuple[float, float]]] = []

    def __call__(self, url: str, max_bytes: int, timeout: tuple[float, float]) -> bytes:
        self.calls.append((url, max_bytes, timeout))
        return self.responses[url]


class FakeResponse:
    def __init__(
        self,
        url: str,
        *,
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        chunks: tuple[bytes, ...] = (b"payload",),
    ) -> None:
        self.url = url
        self.status_code = status_code
        self.headers = headers or {}
        self.chunks = chunks
        self.closed = False

    def iter_content(self, chunk_size: int) -> tuple[bytes, ...]:
        assert chunk_size > 0
        return self.chunks

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError("response contained token=do-not-leak")

    def close(self) -> None:
        self.closed = True


class FakeSession:
    def __init__(self, responses: dict[str, FakeResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, bool, bool, tuple[float, float]]] = []
        self.closed = False

    def get(
        self,
        url: str,
        *,
        stream: bool,
        timeout: tuple[float, float],
        allow_redirects: bool,
    ) -> FakeResponse:
        self.calls.append((url, stream, allow_redirects, timeout))
        return self.responses[url]

    def close(self) -> None:
        self.closed = True


def _card(number: int, *, title: str = "SQL injection playbook") -> tuple[object, ...]:
    return (
        f"card-{number:012x}",
        title,
        "Safely identify SQL injection with parameterized verification.",
        f"https://research.example/card-{number}",
        "Example Research",
        "2026-07-01T00:00:00Z",
        "2026-07-09T00:00:00Z",
        f"{number:064x}",
        '["web", "sqlite"]',
        '["CVE-2026-0001"]',
        '["error-based", "boolean-based"]',
        "high",
        "public",
    )


def _fts_row(card: tuple[object, ...]) -> tuple[object, ...]:
    return (card[0], card[1], card[2], card[8], card[9], card[10])


def _database_bytes(
    tmp_path: Path,
    *,
    cards: list[tuple[object, ...]] | None = None,
    metadata_overrides: dict[str, str] | None = None,
    name: str = "producer.db",
    include_fts: bool = True,
    fts_rows: list[tuple[object, ...]] | None = None,
    cards_primary_key: bool = True,
) -> bytes:
    rows = [_card(1)] if cards is None else cards
    path = tmp_path / name
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    if cards_primary_key:
        connection.execute(
            """
        CREATE TABLE cards(
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            source_url TEXT NOT NULL,
            source_name TEXT NOT NULL,
            published_at TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            products TEXT NOT NULL,
            cves TEXT NOT NULL,
            techniques TEXT NOT NULL,
            confidence TEXT NOT NULL,
            safety TEXT NOT NULL
        )
        """
        )
    else:
        connection.execute(
            """
        CREATE TABLE cards(
            id TEXT NOT NULL,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            source_url TEXT NOT NULL,
            source_name TEXT NOT NULL,
            published_at TEXT NOT NULL,
            fetched_at TEXT NOT NULL,
            content_sha256 TEXT NOT NULL,
            products TEXT NOT NULL,
            cves TEXT NOT NULL,
            techniques TEXT NOT NULL,
            confidence TEXT NOT NULL,
            safety TEXT NOT NULL
        )
        """
        )
    if include_fts:
        connection.execute(
            "CREATE VIRTUAL TABLE cards_fts USING fts5("
            "id, title, summary, products, cves, techniques)"
        )
    metadata = {
        "schema_version": "1",
        "compatibility": "bugbounty-brain-v1",
        "card_count": str(len(rows)),
        "generated_at": GENERATED_AT,
        "source_sha256": SOURCE_SHA256,
    }
    metadata.update(metadata_overrides or {})
    connection.executemany("INSERT INTO metadata(key, value) VALUES (?, ?)", metadata.items())
    connection.executemany(
        """
        INSERT INTO cards(
            id, title, summary, source_url, source_name, published_at, fetched_at,
            content_sha256, products, cves, techniques, confidence, safety
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    if include_fts:
        connection.executemany(
            """
            INSERT INTO cards_fts(id, title, summary, products, cves, techniques)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [_fts_row(row) for row in rows] if fts_rows is None else fts_rows,
        )
    connection.commit()
    connection.close()
    return path.read_bytes()


def _manifest(database: bytes, *, card_count: int = 1, **changes: object) -> bytes:
    document: dict[str, object] = {
        "schema_version": 1,
        "compatibility": "bugbounty-brain-v1",
        "database_filename": "reference_knowledge.db",
        "database_sha256": hashlib.sha256(database).hexdigest(),
        "card_count": card_count,
        "generated_at": GENERATED_AT,
        "source_sha256": SOURCE_SHA256,
    }
    document.update(changes)
    return json.dumps(document, separators=(",", ":")).encode()


def _release_fetcher(
    tmp_path: Path, *, cards: list[tuple[object, ...]] | None = None
) -> FakeFetcher:
    database = _database_bytes(tmp_path, cards=cards)
    return FakeFetcher(
        {MANIFEST_URL: _manifest(database, card_count=len(cards or [_card(1)])), DB_URL: database}
    )


def test_status_reports_not_installed_without_creating_root(tmp_path: Path) -> None:
    root = tmp_path / "public-brain"

    status = BrainStore(root).status()

    assert status.installed is False
    assert status.path is None
    assert status.database_sha256 is None
    assert not root.exists()


def test_clean_install_status_search_and_explain(tmp_path: Path) -> None:
    root = tmp_path / "public-brain"
    fetcher = _release_fetcher(tmp_path)
    store = BrainStore(root, fetcher=fetcher)

    result = store.update()

    expected_hash = hashlib.sha256(fetcher.responses[DB_URL]).hexdigest()
    expected_path = root / f"reference_knowledge-{expected_hash}.db"
    assert result.changed is True
    assert result.status.installed is True
    assert result.status.path == expected_path
    assert result.status.database_sha256 == expected_hash
    assert result.status.card_count == 1
    assert stat.S_IMODE(expected_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((root / "state.json").stat().st_mode) == 0o600
    assert (root / "state.json").stat().st_size < MANIFEST_MAX_BYTES
    assert {path.name for path in root.iterdir()} == {"state.json", expected_path.name}
    assert [call[1] for call in fetcher.calls] == [MANIFEST_MAX_BYTES, DATABASE_MAX_BYTES]
    assert all(call[2] == HTTP_TIMEOUT for call in fetcher.calls)
    assert all(value > 0 for call in fetcher.calls for value in call[2])

    status = store.status()
    assert status == result.status

    matches = store.search("SQL injection", limit=5)
    assert len(matches) == 1
    card = matches[0]
    assert card.id == "card-000000000001"
    assert card.title == "SQL injection playbook"
    assert card.source_url == "https://research.example/card-1"
    assert card.source_name == "Example Research"
    assert card.products == ("web", "sqlite")
    assert card.cves == ("CVE-2026-0001",)
    assert card.techniques == ("error-based", "boolean-based")
    assert card.confidence == "high"
    assert card.safety == "public"
    assert store.explain("card-000000000001") == card
    assert store.explain("missing") is None
    with pytest.raises(FrozenInstanceError):
        result.changed = False  # type: ignore[misc]


def test_v010_timezone_offsets_and_enum_values_remain_compatible(tmp_path: Path) -> None:
    generated_at = "2026-07-10T12:00:00+02:00"
    card = list(_card(1))
    card[5] = "2026-07-01T03:00:00+03:00"
    card[6] = "2026-07-09T04:00:00-04:00"
    card[11] = "low"
    card[12] = "sanitized"
    database = _database_bytes(
        tmp_path,
        cards=[tuple(card)],
        metadata_overrides={"generated_at": generated_at},
    )
    store = BrainStore(
        tmp_path / "brain",
        fetcher=FakeFetcher(
            {
                MANIFEST_URL: _manifest(database, generated_at=generated_at),
                DB_URL: database,
            }
        ),
    )

    result = store.update()

    assert result.status.generated_at == generated_at
    assert store.search("SQL")[0].safety == "sanitized"


def test_multi_term_natural_query_matches_any_sanitized_term(tmp_path: Path) -> None:
    cards = [
        _card(1, title="Reconnaissance attack surface mapping"),
        _card(2, title="Nginx configuration guide"),
    ]
    store = BrainStore(tmp_path / "brain", fetcher=_release_fetcher(tmp_path, cards=cards))
    store.update()

    matches = store.search("reconnaissance attack surface mapping nginx Python")

    assert [card.id for card in matches] == ["card-000000000001", "card-000000000002"]


def test_same_version_fetches_only_manifest_and_returns_unchanged(tmp_path: Path) -> None:
    fetcher = _release_fetcher(tmp_path)
    store = BrainStore(tmp_path / "brain", fetcher=fetcher)
    first = store.update()
    fetcher.calls.clear()

    second = store.update()

    assert second.changed is False
    assert second.status == first.status
    assert [call[0] for call in fetcher.calls] == [MANIFEST_URL]


@pytest.mark.parametrize(
    "changes",
    [
        {"schema_version": 2},
        {"schema_version": True},
        {"compatibility": "private-brain-v1"},
        {"database_filename": "../reference_knowledge.db"},
        {"database_sha256": "A" * 64},
        {"database_sha256": "a" * 63},
        {"card_count": -1},
        {"card_count": True},
        {"generated_at": ""},
        {"generated_at": "2026-07-10T10:00:00"},
        {"generated_at": "2026-07-10"},
        {"generated_at": "not-a-timestamp"},
        {"generated_at": "2" * 41},
        {"source_sha256": ""},
        {"source_sha256": "A" * 64},
        {"source_sha256": "b" * 63},
        {"source_sha256": "g" * 64},
        {"unexpected": "field"},
    ],
)
def test_incompatible_or_non_contract_manifest_is_rejected(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    database = _database_bytes(tmp_path)
    fetcher = FakeFetcher({MANIFEST_URL: _manifest(database, **changes)})

    with pytest.raises(BrainError) as raised:
        BrainStore(tmp_path / "brain", fetcher=fetcher).update()

    assert raised.value.code == "manifest_invalid"
    assert not (tmp_path / "brain").exists()
    assert [call[0] for call in fetcher.calls] == [MANIFEST_URL]


def test_malformed_manifest_preserves_existing_state_and_version(tmp_path: Path) -> None:
    root = tmp_path / "brain"
    initial_fetcher = _release_fetcher(tmp_path)
    store = BrainStore(root, fetcher=initial_fetcher)
    installed = store.update().status
    state_before = (root / "state.json").read_bytes()
    names_before = {path.name for path in root.iterdir()}
    malformed_fetcher = FakeFetcher(
        {
            MANIFEST_URL: _manifest(
                initial_fetcher.responses[DB_URL], generated_at="2026-07-10T10:00:00"
            )
        }
    )

    with pytest.raises(BrainError) as raised:
        BrainStore(root, fetcher=malformed_fetcher).update()

    assert raised.value.code == "manifest_invalid"
    assert (root / "state.json").read_bytes() == state_before
    assert {path.name for path in root.iterdir()} == names_before
    assert store.status() == installed
    assert [call[0] for call in malformed_fetcher.calls] == [MANIFEST_URL]


@pytest.mark.parametrize(
    "payload",
    [
        b"{",
        b"[]",
        b'{"schema_version":1,"schema_version":1}',
        b"\xff",
    ],
)
def test_malformed_manifest_is_rejected(tmp_path: Path, payload: bytes) -> None:
    fetcher = FakeFetcher({MANIFEST_URL: payload})

    with pytest.raises(BrainError) as raised:
        BrainStore(tmp_path / "brain", fetcher=fetcher).update()

    assert raised.value.code == "manifest_invalid"
    assert not (tmp_path / "brain").exists()


def test_oversize_manifest_is_rejected_before_parsing(tmp_path: Path) -> None:
    fetcher = FakeFetcher({MANIFEST_URL: b"x" * (MANIFEST_MAX_BYTES + 1)})

    with pytest.raises(BrainError) as raised:
        BrainStore(tmp_path / "brain", fetcher=fetcher).update()

    assert raised.value.code == "download_too_large"
    assert fetcher.calls[0][1] == MANIFEST_MAX_BYTES
    assert not (tmp_path / "brain").exists()


def test_database_checksum_mismatch_never_creates_state(tmp_path: Path) -> None:
    expected_database = _database_bytes(tmp_path)
    fetcher = FakeFetcher(
        {
            MANIFEST_URL: _manifest(expected_database),
            DB_URL: expected_database + b"tampered",
        }
    )

    with pytest.raises(BrainError) as raised:
        BrainStore(tmp_path / "brain", fetcher=fetcher).update()

    assert raised.value.code == "checksum_mismatch"
    assert not (tmp_path / "brain").exists()


@pytest.mark.parametrize(
    ("database_factory", "manifest_count"),
    [
        (lambda path: b"not a sqlite database", 0),
        (lambda path: _database_bytes(path, include_fts=False), 1),
        (
            lambda path: _database_bytes(
                path, metadata_overrides={"compatibility": "private-brain-v1"}
            ),
            1,
        ),
        (
            lambda path: _database_bytes(path, metadata_overrides={"schema_version": "2"}),
            1,
        ),
        (
            lambda path: _database_bytes(path, metadata_overrides={"card_count": "2"}),
            2,
        ),
    ],
)
def test_invalid_sqlite_schema_metadata_or_card_count_is_rejected(
    tmp_path: Path, database_factory: object, manifest_count: int
) -> None:
    factory = database_factory
    assert callable(factory)
    database = factory(tmp_path)
    fetcher = FakeFetcher(
        {MANIFEST_URL: _manifest(database, card_count=manifest_count), DB_URL: database}
    )

    with pytest.raises(BrainError) as raised:
        BrainStore(tmp_path / "brain", fetcher=fetcher).update()

    assert raised.value.code == "database_invalid"
    assert not (tmp_path / "brain" / "state.json").exists()
    assert not list((tmp_path / "brain").glob(".database-*.tmp"))


def _assert_database_rejected_without_publication(
    tmp_path: Path, database: bytes, *, card_count: int
) -> None:
    root = tmp_path / "brain"
    store = BrainStore(root, fetcher=_release_fetcher(tmp_path))
    installed = store.update().status
    state_before = (root / "state.json").read_bytes()
    names_before = {path.name for path in root.iterdir()}
    malformed_fetcher = FakeFetcher(
        {MANIFEST_URL: _manifest(database, card_count=card_count), DB_URL: database}
    )

    with pytest.raises(BrainError) as raised:
        BrainStore(root, fetcher=malformed_fetcher).update()

    assert raised.value.code == "database_invalid"
    assert (root / "state.json").read_bytes() == state_before
    assert {path.name for path in root.iterdir()} == names_before
    assert store.status() == installed
    assert store.search("SQL")[0].id == "card-000000000001"


@pytest.mark.parametrize(
    ("column", "value"),
    [
        (0, "card-1"),
        (0, "Uppercase-slug-abcdef123456"),
        (1, ""),
        (1, "x" * 141),
        (2, ""),
        (2, "x" * 1_001),
        (3, "http://research.example/card"),
        (3, "https:///missing-host"),
        (3, "https://user:password@research.example/card"),
        (3, "x" * 2_049),
        (4, ""),
        (4, "x" * 121),
        (5, "not-a-timestamp"),
        (5, "2026-07-01T00:00:00"),
        (5, "2" * 41),
        (6, "2026-07-09T00:00:00"),
        (7, "A" * 64),
        (7, "a" * 63),
        (8, "not-json"),
        (8, json.dumps(["product"] * 21)),
        (8, json.dumps([1])),
        (8, json.dumps([""])),
        (9, json.dumps(["CVE-2026-123"])),
        (9, json.dumps(["CVE-2026-0001"] * 51)),
        (10, json.dumps(["technique"] * 31)),
        (11, "certain"),
        (12, "authorized-testing-only"),
    ],
)
def test_malformed_card_row_is_rejected_before_state_publication(
    tmp_path: Path, column: int, value: object
) -> None:
    card = list(_card(2, title="Cross-site scripting"))
    card[column] = value
    database = _database_bytes(tmp_path, cards=[tuple(card)], name="malformed-card.db")

    _assert_database_rejected_without_publication(tmp_path, database, card_count=1)


@pytest.mark.parametrize("fts_column", range(1, 6))
def test_fts_mismatched_selected_value_is_rejected_before_state_publication(
    tmp_path: Path, fts_column: int
) -> None:
    card = _card(2, title="Cross-site scripting")
    fts_row = list(_fts_row(card))
    fts_row[fts_column] = f"mismatched-{fts_column}"
    database = _database_bytes(
        tmp_path,
        cards=[card],
        name="mismatched-fts.db",
        fts_rows=[tuple(fts_row)],
    )

    _assert_database_rejected_without_publication(tmp_path, database, card_count=1)


def test_fts_duplicate_id_and_missing_card_are_rejected_before_state_publication(
    tmp_path: Path,
) -> None:
    cards = [_card(2), _card(3)]
    duplicate = _fts_row(cards[0])
    database = _database_bytes(
        tmp_path,
        cards=cards,
        name="duplicate-fts.db",
        fts_rows=[duplicate, duplicate],
    )

    _assert_database_rejected_without_publication(tmp_path, database, card_count=2)


def test_duplicate_card_ids_are_rejected_before_state_publication(tmp_path: Path) -> None:
    card = _card(2)
    database = _database_bytes(
        tmp_path,
        cards=[card, card],
        name="duplicate-cards.db",
        cards_primary_key=False,
    )

    _assert_database_rejected_without_publication(tmp_path, database, card_count=2)


def test_fts_missing_and_extra_ids_are_rejected_before_state_publication(tmp_path: Path) -> None:
    card = _card(2)
    extra = list(_fts_row(card))
    extra[0] = "extra-card-abcdef123456"
    database = _database_bytes(
        tmp_path,
        cards=[card],
        name="missing-extra-fts.db",
        fts_rows=[tuple(extra)],
    )

    _assert_database_rejected_without_publication(tmp_path, database, card_count=1)


def test_failed_new_release_preserves_previous_state_and_database(tmp_path: Path) -> None:
    root = tmp_path / "brain"
    first_fetcher = _release_fetcher(tmp_path)
    first_store = BrainStore(root, fetcher=first_fetcher)
    first = first_store.update()
    assert first.status.path is not None
    state_before = (root / "state.json").read_bytes()
    database_before = first.status.path.read_bytes()
    names_before = {path.name for path in root.iterdir()}

    second_database = _database_bytes(
        tmp_path,
        cards=[_card(2, title="Cross-site scripting")],
        metadata_overrides={"source_sha256": "wrong-source"},
        name="producer-v2.db",
    )
    second_fetcher = FakeFetcher(
        {MANIFEST_URL: _manifest(second_database), DB_URL: second_database}
    )

    with pytest.raises(BrainError) as raised:
        BrainStore(root, fetcher=second_fetcher).update()

    assert raised.value.code == "database_invalid"
    assert (root / "state.json").read_bytes() == state_before
    assert first.status.path.read_bytes() == database_before
    assert {path.name for path in root.iterdir()} == names_before
    assert first_store.search("SQL")[0].id == "card-000000000001"


def test_successful_new_release_keeps_previous_database_for_rollback(tmp_path: Path) -> None:
    root = tmp_path / "brain"
    first = BrainStore(root, fetcher=_release_fetcher(tmp_path)).update()
    assert first.status.path is not None
    first_path = first.status.path
    first_bytes = first_path.read_bytes()
    second_database = _database_bytes(
        tmp_path,
        cards=[_card(2, title="Cross-site scripting")],
        name="producer-v2.db",
    )

    second = BrainStore(
        root,
        fetcher=FakeFetcher({MANIFEST_URL: _manifest(second_database), DB_URL: second_database}),
    ).update()

    assert second.changed is True
    assert second.status.path != first_path
    assert first_path.read_bytes() == first_bytes
    assert len(list(root.glob("reference_knowledge-*.db"))) == 2


def test_atomic_state_replace_failure_rolls_back_new_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "brain"
    first = BrainStore(root, fetcher=_release_fetcher(tmp_path)).update()
    assert first.status.path is not None
    state_before = (root / "state.json").read_bytes()
    names_before = {path.name for path in root.iterdir()}
    second_database = _database_bytes(
        tmp_path,
        cards=[_card(2, title="Cross-site scripting")],
        name="producer-v2.db",
    )
    store = BrainStore(
        root,
        fetcher=FakeFetcher({MANIFEST_URL: _manifest(second_database), DB_URL: second_database}),
    )

    def reject_replace(source: str | Path, destination: str | Path) -> None:
        del source, destination
        raise PermissionError

    monkeypatch.setattr(brain.os, "replace", reject_replace)

    with pytest.raises(BrainError) as raised:
        store.update()

    assert raised.value.code == "install_failed"
    assert (root / "state.json").read_bytes() == state_before
    assert {path.name for path in root.iterdir()} == names_before
    assert first.status.path.exists()


def test_state_database_basename_cannot_traverse_root(tmp_path: Path) -> None:
    root = tmp_path / "brain"
    store = BrainStore(root, fetcher=_release_fetcher(tmp_path))
    store.update()
    state_path = root / "state.json"
    state = json.loads(state_path.read_text())
    state["database_basename"] = "../outside.db"
    state_path.write_text(json.dumps(state))

    with pytest.raises(BrainError) as raised:
        store.status()

    assert raised.value.code == "state_invalid"


def test_malformed_existing_state_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "brain"
    root.mkdir()
    (root / "state.json").write_text('{"database_basename":"missing"}')

    with pytest.raises(BrainError) as raised:
        BrainStore(root).status()

    assert raised.value.code == "state_invalid"


def test_corrupt_installed_database_fails_closed_in_status(tmp_path: Path) -> None:
    store = BrainStore(tmp_path / "brain", fetcher=_release_fetcher(tmp_path))
    result = store.update()
    assert result.status.path is not None
    with result.status.path.open("ab") as handle:
        handle.write(b"tampered")

    with pytest.raises(BrainError) as raised:
        store.status()

    assert raised.value.code == "state_invalid"


def test_status_never_opens_sqlite_or_private_stores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = BrainStore(tmp_path / "brain", fetcher=_release_fetcher(tmp_path))
    installed = store.update().status

    def reject_sqlite(*args: object, **kwargs: object) -> sqlite3.Connection:
        del args, kwargs
        raise AssertionError("status must not open a database")

    monkeypatch.setattr(brain.sqlite3, "connect", reject_sqlite)

    assert store.status() == installed


def test_search_uses_immutable_query_only_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = BrainStore(tmp_path / "brain", fetcher=_release_fetcher(tmp_path))
    result = store.update()
    real_connect = sqlite3.connect
    calls: list[tuple[str, bool]] = []
    statements: list[str] = []

    class RecordingConnection:
        def __init__(self, database: str, *, uri: bool) -> None:
            calls.append((database, uri))
            self.connection = real_connect(database, uri=uri)

        def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
            statements.append(sql.strip())
            return self.connection.execute(sql, parameters)

        def close(self) -> None:
            self.connection.close()

    monkeypatch.setattr(brain.sqlite3, "connect", RecordingConnection)

    assert store.search("SQL")

    assert result.status.path is not None
    assert calls == [(f"{result.status.path.as_uri()}?mode=ro&immutable=1", True)]
    assert statements[0] == "PRAGMA query_only=ON"


@pytest.mark.parametrize(
    "query",
    ['"', "*", "NEAR(", "SQL OR 1", "-SQL", "title:SQL", 'SQL" OR *', "CVE-2026-0001"],
)
def test_fts_metacharacters_never_reach_sqlite_as_operators(tmp_path: Path, query: str) -> None:
    store = BrainStore(tmp_path / "brain", fetcher=_release_fetcher(tmp_path))
    store.update()

    result = store.search(query)

    assert isinstance(result, tuple)


def test_empty_query_and_public_five_card_maximum(tmp_path: Path) -> None:
    cards = [_card(number, title=f"Shared testing topic {number}") for number in range(1, 8)]
    store = BrainStore(tmp_path / "brain", fetcher=_release_fetcher(tmp_path, cards=cards))
    store.update()

    assert store.search("   **   ") == ()
    assert len(store.search("Shared testing", limit=1000)) == 5
    assert len(store.search("Shared testing", limit=0)) == 1


def test_malformed_card_json_arrays_fail_closed(tmp_path: Path) -> None:
    malformed = list(_card(1))
    malformed[8] = "not-json"
    cards = [tuple(malformed)]
    store = BrainStore(tmp_path / "brain", fetcher=_release_fetcher(tmp_path, cards=cards))

    with pytest.raises(BrainError) as raised:
        store.update()

    assert raised.value.code == "database_invalid"
    assert not (tmp_path / "brain" / "state.json").exists()


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/TrueNix/bugbounty-brain/releases/latest/download/file",
        "https://objects.githubusercontent.com/github-production-release-asset/file",
        "https://release-assets.githubusercontent.com/github-production-release-asset/file?sig=x",
    ],
)
def test_download_url_helper_accepts_only_allowlisted_https_hosts(url: str) -> None:
    _validate_download_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/file",
        "https://example.com/file",
        "https://github.com.example.com/file",
        "https://github.com@127.0.0.1/file",
        "https://user:password@github.com/file",
        "https://github.com:443/file",
        "https://127.0.0.1/file",
        "https://2130706433/file",
        "https://0177.0.0.1/file",
        "https://[::1]/file",
        "https://github.com\\@example.com/file",
        "https://%67ithub.com/file",
    ],
)
def test_download_url_helper_rejects_ambiguous_or_untrusted_urls(url: str) -> None:
    with pytest.raises(BrainError) as raised:
        _validate_download_url(url)

    assert raised.value.code == "untrusted_url"
    assert "password" not in str(raised.value)


def test_default_fetch_streams_across_only_trusted_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = MANIFEST_URL
    second = "https://objects.githubusercontent.com/release/manifest"
    final = "https://release-assets.githubusercontent.com/release/manifest?signature=secret"
    responses = {
        first: FakeResponse(first, status_code=302, headers={"Location": second}, chunks=()),
        second: FakeResponse(second, status_code=307, headers={"Location": final}, chunks=()),
        final: FakeResponse(
            final,
            headers={"Content-Length": "7"},
            chunks=(b"pay", b"", b"load"),
        ),
    }
    session = FakeSession(responses)
    monkeypatch.setattr(brain.requests, "Session", lambda: session)

    payload = _default_fetch(first, 7, HTTP_TIMEOUT)

    assert payload == b"payload"
    assert [call[0] for call in session.calls] == [first, second, final]
    assert all(call[1:] == (True, False, HTTP_TIMEOUT) for call in session.calls)
    assert all(response.closed for response in responses.values())
    assert session.closed is True


def test_default_fetch_rejects_untrusted_redirect_before_requesting_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeResponse(
        MANIFEST_URL,
        status_code=302,
        headers={"Location": "https://127.0.0.1/private"},
        chunks=(),
    )
    session = FakeSession({MANIFEST_URL: response})
    monkeypatch.setattr(brain.requests, "Session", lambda: session)

    with pytest.raises(BrainError) as raised:
        _default_fetch(MANIFEST_URL, MANIFEST_MAX_BYTES, HTTP_TIMEOUT)

    assert raised.value.code == "untrusted_url"
    assert [call[0] for call in session.calls] == [MANIFEST_URL]
    assert response.closed is True


def test_default_fetch_validates_response_final_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeResponse("https://example.com/stolen", chunks=(b"secret",))
    session = FakeSession({MANIFEST_URL: response})
    monkeypatch.setattr(brain.requests, "Session", lambda: session)

    with pytest.raises(BrainError) as raised:
        _default_fetch(MANIFEST_URL, MANIFEST_MAX_BYTES, HTTP_TIMEOUT)

    assert raised.value.code == "untrusted_url"
    assert response.closed is True


def test_default_fetch_bounds_the_number_of_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    urls = [f"https://github.com/release/hop-{number}" for number in range(7)]
    responses = {
        url: FakeResponse(
            url,
            status_code=302,
            headers={"Location": urls[index + 1]},
            chunks=(),
        )
        for index, url in enumerate(urls[:-1])
    }
    session = FakeSession(responses)
    monkeypatch.setattr(brain.requests, "Session", lambda: session)

    with pytest.raises(BrainError) as raised:
        _default_fetch(urls[0], MANIFEST_MAX_BYTES, HTTP_TIMEOUT)

    assert raised.value.code == "download_failed"
    assert len(session.calls) == 6


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(MANIFEST_URL, headers={"Content-Length": "8"}, chunks=(b"payload!",)),
        FakeResponse(MANIFEST_URL, chunks=(b"pay", b"load!")),
    ],
)
def test_default_fetch_enforces_cap_from_headers_and_stream(
    monkeypatch: pytest.MonkeyPatch, response: FakeResponse
) -> None:
    session = FakeSession({MANIFEST_URL: response})
    monkeypatch.setattr(brain.requests, "Session", lambda: session)

    with pytest.raises(BrainError) as raised:
        _default_fetch(MANIFEST_URL, 7, HTTP_TIMEOUT)

    assert raised.value.code == "download_too_large"
    assert response.closed is True


def test_default_fetch_http_error_does_not_leak_response_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = FakeResponse(MANIFEST_URL, status_code=403, chunks=())
    session = FakeSession({MANIFEST_URL: response})
    monkeypatch.setattr(brain.requests, "Session", lambda: session)

    with pytest.raises(BrainError) as raised:
        _default_fetch(MANIFEST_URL, MANIFEST_MAX_BYTES, HTTP_TIMEOUT)

    assert raised.value.code == "download_failed"
    assert "do-not-leak" not in str(raised.value)


def test_store_uses_default_fetcher_when_none_is_injected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = _database_bytes(tmp_path)
    responses = {MANIFEST_URL: _manifest(database), DB_URL: database}
    calls: list[tuple[str, int, tuple[float, float]]] = []

    def mocked_default(url: str, max_bytes: int, timeout: tuple[float, float]) -> bytes:
        calls.append((url, max_bytes, timeout))
        return responses[url]

    monkeypatch.setattr(brain, "_default_fetch", mocked_default)

    result = BrainStore(tmp_path / "brain").update()

    assert result.changed is True
    assert [call[0] for call in calls] == [MANIFEST_URL, DB_URL]
