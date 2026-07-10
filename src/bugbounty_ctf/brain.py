"""Secure, read-only consumer for the separately released public brain."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, cast
from urllib.parse import urljoin, urlsplit

import requests

MANIFEST_URL: Final = (
    "https://github.com/TrueNix/bugbounty-brain/releases/latest/download/brain-manifest.json"
)
DATABASE_URL: Final = (
    "https://github.com/TrueNix/bugbounty-brain/releases/latest/download/reference_knowledge.db"
)
DEFAULT_ROOT: Final = Path("~/.hermes/bugbounty-brain")

MANIFEST_MAX_BYTES: Final = 64 * 1024
DATABASE_MAX_BYTES: Final = 100 * 1024 * 1024
HTTP_TIMEOUT: Final = (5.0, 30.0)
SCHEMA_VERSION: Final = 1
COMPATIBILITY: Final = "bugbounty-brain-v1"
DATABASE_FILENAME: Final = "reference_knowledge.db"

_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}\Z")
_STATE_FILENAME: Final = "state.json"
_STATE_MAX_BYTES: Final = 64 * 1024
_MANIFEST_KEYS: Final = frozenset(
    {
        "schema_version",
        "compatibility",
        "database_filename",
        "database_sha256",
        "card_count",
        "generated_at",
        "source_sha256",
    }
)
_METADATA_KEYS: Final = frozenset(
    {"schema_version", "compatibility", "card_count", "generated_at", "source_sha256"}
)
_CARD_COLUMNS: Final = (
    "id",
    "title",
    "summary",
    "source_url",
    "source_name",
    "published_at",
    "fetched_at",
    "content_sha256",
    "products",
    "cves",
    "techniques",
    "confidence",
    "safety",
)
_FTS_COLUMNS: Final = ("id", "title", "summary", "products", "cves", "techniques")
_TRUSTED_DOWNLOAD_HOSTS: Final = frozenset(
    {"github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
)
_REDIRECT_STATUSES: Final = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECTS: Final = 5
_STREAM_CHUNK_BYTES: Final = 64 * 1024


class Fetcher(Protocol):
    """Callable used to retrieve one capped release asset."""

    def __call__(self, url: str, max_bytes: int, timeout: tuple[float, float], /) -> bytes: ...


class _HTTPResponse(Protocol):
    url: str
    status_code: int
    headers: Mapping[str, str]

    def iter_content(self, chunk_size: int) -> Iterable[bytes]: ...

    def raise_for_status(self) -> None: ...

    def close(self) -> None: ...


class _HTTPSession(Protocol):
    def get(
        self,
        url: str,
        *,
        stream: bool,
        timeout: tuple[float, float],
        allow_redirects: bool,
    ) -> _HTTPResponse: ...

    def close(self) -> None: ...


class BrainError(RuntimeError):
    """A typed, credential-safe failure with a concrete recovery action."""

    code: str
    action: str

    def __init__(self, code: str, message: str, action: str) -> None:
        self.code = code
        self.action = action
        super().__init__(f"{message} Action: {action}")


@dataclass(frozen=True, slots=True)
class BrainStatus:
    """The locally installed public-brain version, if any."""

    installed: bool
    path: Path | None
    schema_version: int | None = None
    compatibility: str | None = None
    database_filename: str | None = None
    database_sha256: str | None = None
    card_count: int | None = None
    generated_at: str | None = None
    source_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class BrainUpdateResult:
    """Result of checking and, when needed, installing a public-brain release."""

    changed: bool
    status: BrainStatus


@dataclass(frozen=True, slots=True)
class BrainCard:
    """A public reference card with its source and integrity provenance."""

    id: str
    title: str
    summary: str
    source_url: str
    source_name: str
    published_at: str
    fetched_at: str
    content_sha256: str
    products: tuple[str, ...]
    cves: tuple[str, ...]
    techniques: tuple[str, ...]
    confidence: str
    safety: str


@dataclass(frozen=True, slots=True)
class _Manifest:
    schema_version: int
    compatibility: str
    database_filename: str
    database_sha256: str
    card_count: int
    generated_at: str
    source_sha256: str

    @property
    def installed_basename(self) -> str:
        return f"reference_knowledge-{self.database_sha256}.db"


class BrainStore:
    """Install and query the public brain without touching private stores."""

    def __init__(self, root: str | Path | None = None, fetcher: Fetcher | None = None) -> None:
        selected_root = DEFAULT_ROOT if root is None else Path(root)
        self._root = selected_root.expanduser().resolve()
        self._fetcher = fetcher

    def status(self) -> BrainStatus:
        """Return verified local status without creating local state."""
        state = self._read_state()
        if state is None:
            return BrainStatus(installed=False, path=None)
        manifest, database_path = state
        actual_hash = _sha256_file(database_path)
        if actual_hash != manifest.database_sha256:
            raise _error(
                "state_invalid",
                "The installed public-brain database does not match its state pointer.",
                "Run update after removing only the invalid state pointer.",
            )
        return _status_from_manifest(manifest, database_path)

    def update(self) -> BrainUpdateResult:
        """Fetch, verify, and atomically point at the latest public release."""
        manifest = _parse_manifest(self._fetch(MANIFEST_URL, MANIFEST_MAX_BYTES))
        current = self.status()
        if current.installed and current.database_sha256 == manifest.database_sha256:
            return BrainUpdateResult(changed=False, status=current)

        database = self._fetch(DATABASE_URL, DATABASE_MAX_BYTES)
        if hashlib.sha256(database).hexdigest() != manifest.database_sha256:
            raise _error(
                "checksum_mismatch",
                "The downloaded public-brain database failed SHA-256 verification.",
                "Keep the current version and retry the update later.",
            )

        self._ensure_root()
        temporary_path = self._write_staged_database(database)
        final_path = self._root / manifest.installed_basename
        created_final = False
        try:
            _validate_database(temporary_path, manifest)
            if final_path.exists() or final_path.is_symlink():
                _validate_version_path(final_path, manifest)
            else:
                os.link(temporary_path, final_path)
                os.chmod(final_path, 0o600)
                created_final = True
            self._write_state(manifest)
        except BrainError:
            if created_final:
                _best_effort_unlink(final_path)
            raise
        except OSError:
            if created_final:
                _best_effort_unlink(final_path)
            raise _error(
                "install_failed",
                "The verified public-brain release could not be installed atomically.",
                "Check the brain directory permissions and retry.",
            ) from None
        finally:
            _best_effort_unlink(temporary_path)

        return BrainUpdateResult(
            changed=True,
            status=_status_from_manifest(manifest, final_path),
        )

    def search(self, query: str, limit: int = 5) -> tuple[BrainCard, ...]:
        """Return up to five public cards matching safely quoted FTS terms."""
        fts_query = _safe_fts_query(query)
        if not fts_query:
            return ()
        public_limit = max(1, min(limit, 5))
        status = self.status()
        database_path = _require_installed_path(status)
        connection = _open_read_only(database_path)
        try:
            rows = connection.execute(
                """
                SELECT c.id, c.title, c.summary, c.source_url, c.source_name,
                       c.published_at, c.fetched_at, c.content_sha256, c.products,
                       c.cves, c.techniques, c.confidence, c.safety
                FROM cards_fts
                JOIN cards AS c ON c.id = cards_fts.id
                WHERE cards_fts MATCH ?
                ORDER BY bm25(cards_fts), c.id
                LIMIT ?
                """,
                (fts_query, public_limit),
            ).fetchall()
            return tuple(_card_from_row(row) for row in rows)
        except BrainError:
            raise
        except sqlite3.Error:
            raise _error(
                "database_invalid",
                "The installed public-brain database could not be searched safely.",
                "Run update to install a verified release.",
            ) from None
        finally:
            connection.close()

    def explain(self, card_id: str) -> BrainCard | None:
        """Return one exact public card without enabling database writes."""
        status = self.status()
        database_path = _require_installed_path(status)
        connection = _open_read_only(database_path)
        try:
            rows = connection.execute(
                """
                SELECT id, title, summary, source_url, source_name, published_at,
                       fetched_at, content_sha256, products, cves, techniques,
                       confidence, safety
                FROM cards
                WHERE id = ?
                LIMIT 2
                """,
                (card_id,),
            ).fetchall()
            if not rows:
                return None
            if len(rows) != 1:
                raise _error(
                    "database_invalid",
                    "The installed public-brain database contains duplicate card identifiers.",
                    "Run update to install a verified release.",
                )
            return _card_from_row(rows[0])
        except BrainError:
            raise
        except sqlite3.Error:
            raise _error(
                "database_invalid",
                "The installed public-brain database could not be read safely.",
                "Run update to install a verified release.",
            ) from None
        finally:
            connection.close()

    def _fetch(self, url: str, max_bytes: int) -> bytes:
        fetcher = _default_fetch if self._fetcher is None else self._fetcher
        try:
            payload = fetcher(url, max_bytes, HTTP_TIMEOUT)
        except BrainError:
            raise
        except Exception:
            raise _error(
                "download_failed",
                "A public-brain release asset could not be downloaded.",
                "Check network access and retry.",
            ) from None
        if not isinstance(payload, bytes):
            raise _error(
                "download_failed",
                "The public-brain downloader returned an invalid payload.",
                "Use a fetcher that returns bytes and retry.",
            )
        if len(payload) > max_bytes:
            raise _error(
                "download_too_large",
                "A public-brain release asset exceeded its byte limit.",
                "Keep the current version and verify the producer release.",
            )
        return payload

    def _read_state(self) -> tuple[_Manifest, Path] | None:
        if not self._root.exists():
            return None
        if not self._root.is_dir():
            raise _state_error()
        state_path = self._root / _STATE_FILENAME
        if not state_path.exists() and not state_path.is_symlink():
            return None
        try:
            state_stat = state_path.lstat()
            if stat.S_ISLNK(state_stat.st_mode) or not stat.S_ISREG(state_stat.st_mode):
                raise _state_error()
            if state_stat.st_size > _STATE_MAX_BYTES:
                raise _state_error()
            document = _load_json_object(state_path.read_bytes(), "state_invalid")
        except BrainError:
            raise
        except OSError:
            raise _state_error() from None
        if set(document) != {"database_basename", "manifest"}:
            raise _state_error()
        manifest_document = document["manifest"]
        if not isinstance(manifest_document, dict):
            raise _state_error()
        manifest = _parse_manifest_document(
            cast("dict[str, object]", manifest_document), "state_invalid"
        )
        basename = document["database_basename"]
        if not isinstance(basename, str) or basename != manifest.installed_basename:
            raise _state_error()
        database_path = self._root / basename
        if database_path.parent != self._root:
            raise _state_error()
        try:
            database_stat = database_path.lstat()
        except OSError:
            raise _state_error() from None
        if stat.S_ISLNK(database_stat.st_mode) or not stat.S_ISREG(database_stat.st_mode):
            raise _state_error()
        return manifest, database_path

    def _ensure_root(self) -> None:
        try:
            self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not self._root.is_dir():
                raise OSError
        except OSError:
            raise _error(
                "install_failed",
                "The public-brain directory could not be created.",
                "Check the parent directory permissions and retry.",
            ) from None

    def _write_staged_database(self, payload: bytes) -> Path:
        descriptor = -1
        path: Path | None = None
        try:
            descriptor, raw_path = tempfile.mkstemp(
                prefix=".database-", suffix=".tmp", dir=self._root
            )
            path = Path(raw_path)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(path, 0o600)
            return path
        except OSError:
            if descriptor >= 0:
                os.close(descriptor)
            if path is not None:
                _best_effort_unlink(path)
            raise _error(
                "install_failed",
                "The downloaded public-brain database could not be staged.",
                "Check free space and directory permissions, then retry.",
            ) from None

    def _write_state(self, manifest: _Manifest) -> None:
        document = {
            "database_basename": manifest.installed_basename,
            "manifest": _manifest_document(manifest),
        }
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
        descriptor = -1
        temporary_path: Path | None = None
        try:
            descriptor, raw_path = tempfile.mkstemp(prefix=".state-", suffix=".tmp", dir=self._root)
            temporary_path = Path(raw_path)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, self._root / _STATE_FILENAME)
            temporary_path = None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_path is not None:
                _best_effort_unlink(temporary_path)


def _error(code: str, message: str, action: str) -> BrainError:
    return BrainError(code, message, action)


def _best_effort_unlink(path: Path) -> None:
    with suppress(OSError):
        path.unlink(missing_ok=True)


def _validate_download_url(url: str) -> None:
    """Reject any URL outside the exact HTTPS release-asset trust boundary."""
    if not isinstance(url, str) or any(ord(character) <= 32 for character in url) or "\\" in url:
        raise _untrusted_url_error()
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise _untrusted_url_error() from None
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or hostname.lower() not in _TRUSTED_DOWNLOAD_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.netloc.lower() != hostname.lower()
    ):
        raise _untrusted_url_error()


def _untrusted_url_error() -> BrainError:
    return _error(
        "untrusted_url",
        "A public-brain download URL crossed the trusted HTTPS host boundary.",
        "Keep the current version and verify the producer release location.",
    )


def _default_fetch(url: str, max_bytes: int, timeout: tuple[float, float]) -> bytes:
    """Stream one asset through a manually validated, bounded redirect chain."""
    _validate_download_url(url)
    session = cast("_HTTPSession", requests.Session())
    current_url = url
    redirect_count = 0
    try:
        while True:
            _validate_download_url(current_url)
            response: _HTTPResponse | None = None
            try:
                response = session.get(
                    current_url,
                    stream=True,
                    timeout=timeout,
                    allow_redirects=False,
                )
                if not isinstance(response.url, str):
                    raise _download_error()
                _validate_download_url(response.url)
                if type(response.status_code) is not int:
                    raise _download_error()

                if response.status_code in _REDIRECT_STATUSES:
                    location = response.headers.get("Location")
                    if (
                        not isinstance(location, str)
                        or not location
                        or redirect_count >= _MAX_REDIRECTS
                    ):
                        raise _download_error()
                    next_url = urljoin(response.url, location)
                    _validate_download_url(next_url)
                    redirect_count += 1
                    current_url = next_url
                    continue
                if 300 <= response.status_code < 400:
                    raise _download_error()

                response.raise_for_status()
                content_length = response.headers.get("Content-Length")
                if isinstance(content_length, str):
                    try:
                        if int(content_length) > max_bytes:
                            raise _too_large_error()
                    except ValueError:
                        pass

                payload = bytearray()
                for chunk in response.iter_content(chunk_size=_STREAM_CHUNK_BYTES):
                    if not isinstance(chunk, bytes):
                        raise _download_error()
                    if not chunk:
                        continue
                    if len(payload) + len(chunk) > max_bytes:
                        raise _too_large_error()
                    payload.extend(chunk)
                return bytes(payload)
            except BrainError:
                raise
            except (requests.RequestException, OSError):
                raise _download_error() from None
            finally:
                if response is not None:
                    response.close()
    finally:
        session.close()


def _download_error() -> BrainError:
    return _error(
        "download_failed",
        "A public-brain release asset could not be downloaded safely.",
        "Check network access and retry without changing the installed version.",
    )


def _too_large_error() -> BrainError:
    return _error(
        "download_too_large",
        "A public-brain release asset exceeded its byte limit.",
        "Keep the current version and verify the producer release.",
    )


def _state_error() -> BrainError:
    return _error(
        "state_invalid",
        "The public-brain state pointer is missing data, unsafe, or corrupt.",
        "Remove only state.json and run update to reinstall a verified release.",
    )


def _load_json_object(payload: bytes, error_code: str) -> dict[str, object]:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError
            document[key] = value
        return document

    try:
        decoded = payload.decode("utf-8")
        value = json.loads(decoded, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        if error_code == "state_invalid":
            raise _state_error() from None
        raise _manifest_error() from None
    if not isinstance(value, dict):
        if error_code == "state_invalid":
            raise _state_error()
        raise _manifest_error()
    return cast("dict[str, object]", value)


def _parse_manifest(payload: bytes) -> _Manifest:
    return _parse_manifest_document(
        _load_json_object(payload, "manifest_invalid"), "manifest_invalid"
    )


def _parse_manifest_document(document: dict[str, object], error_code: str) -> _Manifest:
    if set(document) != _MANIFEST_KEYS:
        raise _state_error() if error_code == "state_invalid" else _manifest_error()
    schema_version = document["schema_version"]
    compatibility = document["compatibility"]
    database_filename = document["database_filename"]
    database_sha256 = document["database_sha256"]
    card_count = document["card_count"]
    generated_at = document["generated_at"]
    source_sha256 = document["source_sha256"]
    valid = (
        type(schema_version) is int
        and schema_version == SCHEMA_VERSION
        and compatibility == COMPATIBILITY
        and database_filename == DATABASE_FILENAME
        and isinstance(database_sha256, str)
        and _SHA256_RE.fullmatch(database_sha256) is not None
        and type(card_count) is int
        and card_count >= 0
        and isinstance(generated_at, str)
        and bool(generated_at)
        and isinstance(source_sha256, str)
        and bool(source_sha256)
    )
    if not valid:
        raise _state_error() if error_code == "state_invalid" else _manifest_error()
    return _Manifest(
        schema_version=cast("int", schema_version),
        compatibility=cast("str", compatibility),
        database_filename=cast("str", database_filename),
        database_sha256=cast("str", database_sha256),
        card_count=cast("int", card_count),
        generated_at=cast("str", generated_at),
        source_sha256=cast("str", source_sha256),
    )


def _manifest_error() -> BrainError:
    return _error(
        "manifest_invalid",
        "The public-brain manifest is malformed or incompatible with this consumer.",
        "Keep the current version and verify the producer release.",
    )


def _manifest_document(manifest: _Manifest) -> dict[str, object]:
    return {
        "schema_version": manifest.schema_version,
        "compatibility": manifest.compatibility,
        "database_filename": manifest.database_filename,
        "database_sha256": manifest.database_sha256,
        "card_count": manifest.card_count,
        "generated_at": manifest.generated_at,
        "source_sha256": manifest.source_sha256,
    }


def _status_from_manifest(manifest: _Manifest, database_path: Path) -> BrainStatus:
    return BrainStatus(
        installed=True,
        path=database_path,
        schema_version=manifest.schema_version,
        compatibility=manifest.compatibility,
        database_filename=manifest.database_filename,
        database_sha256=manifest.database_sha256,
        card_count=manifest.card_count,
        generated_at=manifest.generated_at,
        source_sha256=manifest.source_sha256,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        raise _state_error() from None
    return digest.hexdigest()


def _open_read_only(path: Path) -> sqlite3.Connection:
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True)
        connection.execute("PRAGMA query_only=ON")
        return connection
    except sqlite3.Error:
        if connection is not None:
            connection.close()
        raise _error(
            "database_invalid",
            "The installed public-brain database could not be opened read-only.",
            "Run update to install a verified release.",
        ) from None


def _validate_database(path: Path, manifest: _Manifest) -> None:
    connection = _open_read_only(path)
    try:
        quick_check = connection.execute("PRAGMA quick_check").fetchall()
        if quick_check != [("ok",)]:
            raise _database_error()
        if _table_columns(connection, "metadata") != ("key", "value"):
            raise _database_error()
        if _table_columns(connection, "cards") != _CARD_COLUMNS:
            raise _database_error()
        if _table_columns(connection, "cards_fts") != _FTS_COLUMNS:
            raise _database_error()
        fts_row = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'cards_fts'"
        ).fetchone()
        if (
            fts_row is None
            or not isinstance(fts_row[0], str)
            or re.search(r"\bUSING\s+fts5\s*\(", fts_row[0], re.IGNORECASE) is None
        ):
            raise _database_error()

        metadata_rows = connection.execute("SELECT key, value FROM metadata").fetchall()
        if any(
            not isinstance(key, str) or not isinstance(value, str) for key, value in metadata_rows
        ):
            raise _database_error()
        metadata = dict(cast("list[tuple[str, str]]", metadata_rows))
        expected_metadata = {
            "schema_version": str(manifest.schema_version),
            "compatibility": manifest.compatibility,
            "card_count": str(manifest.card_count),
            "generated_at": manifest.generated_at,
            "source_sha256": manifest.source_sha256,
        }
        if (
            len(metadata_rows) != len(metadata)
            or set(metadata) != _METADATA_KEYS
            or metadata != expected_metadata
        ):
            raise _database_error()
        card_count = connection.execute("SELECT COUNT(*) FROM cards").fetchone()
        fts_count = connection.execute("SELECT COUNT(*) FROM cards_fts").fetchone()
        if card_count != (manifest.card_count,) or fts_count != (manifest.card_count,):
            raise _database_error()
    except BrainError:
        raise
    except sqlite3.Error:
        raise _database_error() from None
    finally:
        connection.close()


def _table_columns(connection: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(cast("str", row[1]) for row in connection.execute(f"PRAGMA table_info({table})"))


def _database_error() -> BrainError:
    return _error(
        "database_invalid",
        "The downloaded public-brain database failed integrity, schema, or metadata checks.",
        "Keep the current version and verify the producer release.",
    )


def _validate_version_path(path: Path, manifest: _Manifest) -> None:
    try:
        path_stat = path.lstat()
    except OSError:
        raise _database_error() from None
    if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
        raise _database_error()
    if _sha256_file(path) != manifest.database_sha256:
        raise _database_error()
    _validate_database(path, manifest)


def _require_installed_path(status: BrainStatus) -> Path:
    if not status.installed or status.path is None:
        raise _error(
            "not_installed",
            "No public-brain release is installed.",
            "Run update before searching the public brain.",
        )
    return status.path


def _safe_fts_query(query: str) -> str:
    terms = re.findall(r"\w+", query, flags=re.UNICODE)
    return " AND ".join(f'"{term[:128]}"' for term in terms[:32] if term)


def _card_from_row(row: tuple[object, ...]) -> BrainCard:
    if len(row) != len(_CARD_COLUMNS):
        raise _database_error()
    text_values = row[:8] + row[11:]
    if any(not isinstance(value, str) for value in text_values):
        raise _database_error()
    return BrainCard(
        id=cast("str", row[0]),
        title=cast("str", row[1]),
        summary=cast("str", row[2]),
        source_url=cast("str", row[3]),
        source_name=cast("str", row[4]),
        published_at=cast("str", row[5]),
        fetched_at=cast("str", row[6]),
        content_sha256=cast("str", row[7]),
        products=_json_string_array(row[8]),
        cves=_json_string_array(row[9]),
        techniques=_json_string_array(row[10]),
        confidence=cast("str", row[11]),
        safety=cast("str", row[12]),
    )


def _json_string_array(value: object) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise _database_error()
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        raise _database_error() from None
    if not isinstance(decoded, list) or any(not isinstance(item, str) for item in decoded):
        raise _database_error()
    return tuple(decoded)
