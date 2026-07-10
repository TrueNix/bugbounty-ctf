from __future__ import annotations

import json
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

from bugbounty_ctf import kalibox
from bugbounty_ctf.brain import BrainCard, BrainError, BrainStatus, BrainUpdateResult


class FakeBrainStore:
    def __init__(
        self,
        *,
        status: BrainStatus | None = None,
        update: BrainUpdateResult | None = None,
        cards: tuple[BrainCard, ...] = (),
        explained: BrainCard | None = None,
        error: BrainError | None = None,
    ) -> None:
        self.status_result = status or BrainStatus(installed=False, path=None)
        self.update_result = update or BrainUpdateResult(False, self.status_result)
        self.cards = cards
        self.explained = explained
        self.error = error
        self.calls: list[tuple[object, ...]] = []

    def status(self) -> BrainStatus:
        self.calls.append(("status",))
        if self.error is not None:
            raise self.error
        return self.status_result

    def update(self) -> BrainUpdateResult:
        self.calls.append(("update",))
        if self.error is not None:
            raise self.error
        return self.update_result

    def search(self, query: str, limit: int = 5) -> tuple[BrainCard, ...]:
        self.calls.append(("search", query, limit))
        if self.error is not None:
            raise self.error
        return self.cards

    def explain(self, card_id: str) -> BrainCard | None:
        self.calls.append(("explain", card_id))
        if self.error is not None:
            raise self.error
        return self.explained


def _card() -> BrainCard:
    return BrainCard(
        id="CVE-2026-0001",
        title="SQL injection in Example",
        summary="A public reference summary.",
        source_url="https://example.test/advisory",
        source_name="Example Security",
        published_at="2026-07-01T00:00:00Z",
        fetched_at="2026-07-02T00:00:00Z",
        content_sha256="a" * 64,
        products=("Example Server",),
        cves=("CVE-2026-0001",),
        techniques=("SQL injection", "authentication bypass"),
        confidence="high",
        safety="public",
    )


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _expected_json(value: Any) -> str:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    return json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":")) + "\n"


def _install_seams(
    monkeypatch: pytest.MonkeyPatch, store: FakeBrainStore
) -> list[str | Path | None]:
    roots: list[str | Path | None] = []

    def store_factory(root: str | Path | None = None) -> FakeBrainStore:
        roots.append(root)
        return store

    def forbidden_box() -> None:
        raise AssertionError("brain commands must not construct KaliBox")

    monkeypatch.setattr(kalibox, "BrainStore", store_factory)
    monkeypatch.setattr(kalibox, "KaliBox", forbidden_box)
    return roots


def test_help_documents_brain_without_constructing_container(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        kalibox,
        "KaliBox",
        lambda: (_ for _ in ()).throw(AssertionError("constructed KaliBox")),
    )

    assert kalibox.main(["--help"]) == 0
    top = capsys.readouterr()
    assert "kalibox brain" in top.out
    assert top.err == ""

    assert kalibox.main(["brain", "--help"]) == 0
    brain = capsys.readouterr()
    for command in ("status", "update", "search", "explain"):
        assert command in brain.out
    assert brain.err == ""


def test_top_level_help_documents_explicit_container_escape(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        kalibox,
        "KaliBox",
        lambda: (_ for _ in ()).throw(AssertionError("constructed KaliBox")),
    )

    assert kalibox.main(["--help"]) == 0
    captured = capsys.readouterr()
    assert "kalibox -- <command...>" in captured.out
    assert "host-side" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    "escaped_argv",
    [
        ["brain", "status"],
        ["status"],
        ["up"],
        ["down"],
        ["destroy"],
        ["shell"],
        ["--help"],
    ],
)
def test_double_dash_bypasses_every_host_subcommand_with_unchanged_argv(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    escaped_argv: list[str],
) -> None:
    calls: list[tuple[object, ...]] = []

    class FakeKaliBox:
        class DockerNotFoundError(RuntimeError):
            pass

        def ensure(self, *, provision: bool = True) -> FakeKaliBox:
            calls.append(("ensure", provision))
            return self

        def exec(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(("exec", argv))
            return subprocess.CompletedProcess(argv, 0, "container output\n", "")

    monkeypatch.setattr(kalibox, "KaliBox", FakeKaliBox)
    monkeypatch.setattr(
        kalibox,
        "BrainStore",
        lambda root=None: (_ for _ in ()).throw(AssertionError("constructed BrainStore")),
    )
    assert kalibox.main(["--", *escaped_argv]) == 0
    captured = capsys.readouterr()
    assert captured.out == "container output\n"
    assert captured.err == ""
    assert calls == [("ensure", True), ("exec", escaped_argv)]


def test_bare_double_dash_is_usage_error_without_construction(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        kalibox,
        "KaliBox",
        lambda: (_ for _ in ()).throw(AssertionError("constructed KaliBox")),
    )

    assert kalibox.main(["--"]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("[kalibox] usage error:")
    assert "command" in captured.err


def test_status_emits_deterministic_json_and_uses_root(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    status = BrainStatus(
        installed=True,
        path=tmp_path / "reference.db",
        schema_version=1,
        compatibility="bugbounty-brain-v1",
        database_filename="reference_knowledge.db",
        database_sha256="b" * 64,
        card_count=7,
        generated_at="2026-07-01T00:00:00Z",
        source_sha256="c" * 64,
    )
    store = FakeBrainStore(status=status)
    roots = _install_seams(monkeypatch, store)

    assert kalibox.main(["brain", "status", "--root", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert captured.out == _expected_json(status)
    assert captured.err == ""
    assert roots == [str(tmp_path)]
    assert store.calls == [("status",)]


def test_update_emits_nested_deterministic_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    status = BrainStatus(installed=True, path=tmp_path / "brain.db", card_count=1)
    result = BrainUpdateResult(changed=True, status=status)
    store = FakeBrainStore(update=result)
    _install_seams(monkeypatch, store)

    assert kalibox.main(["brain", "update"]) == 0
    captured = capsys.readouterr()
    assert captured.out == _expected_json(result)
    assert captured.err == ""
    assert store.calls == [("update",)]


def test_search_joins_multiword_query_and_includes_card_provenance(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    card = _card()
    store = FakeBrainStore(cards=(card,))
    _install_seams(monkeypatch, store)

    assert kalibox.main(["brain", "search", "sql", "injection", "oracle", "--limit", "2"]) == 0
    captured = capsys.readouterr()
    assert captured.out == _expected_json([asdict(card)])
    assert captured.err == ""
    assert json.loads(captured.out)[0] == _jsonable(asdict(card))
    assert store.calls == [("search", "sql injection oracle", 2)]


@pytest.mark.parametrize("found", [False, True])
def test_explain_emits_null_or_full_card(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    found: bool,
) -> None:
    card = _card() if found else None
    store = FakeBrainStore(explained=card)
    _install_seams(monkeypatch, store)

    assert kalibox.main(["brain", "explain", "CVE-2026-0001"]) == 0
    captured = capsys.readouterr()
    expected = _expected_json(asdict(card) if card is not None else None)
    assert captured.out == expected
    assert captured.err == ""
    assert store.calls == [("explain", "CVE-2026-0001")]


@pytest.mark.parametrize(
    "args",
    [
        ["brain", "unknown"],
        ["brain", "status", "extra"],
        ["brain", "update", "--root"],
        ["brain", "search"],
        ["brain", "search", "query", "--limit"],
        ["brain", "search", "query", "--limit", "many"],
        ["brain", "search", "query", "--limit", "0"],
        ["brain", "search", "query", "--limit", "6"],
        ["brain", "search", "query", "--unknown"],
        ["brain", "explain"],
        ["brain", "explain", "one", "two"],
    ],
)
def test_malformed_brain_arguments_return_usage_error_without_construction(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    args: list[str],
) -> None:
    monkeypatch.setattr(
        kalibox,
        "BrainStore",
        lambda root=None: (_ for _ in ()).throw(AssertionError("constructed BrainStore")),
        raising=False,
    )
    monkeypatch.setattr(
        kalibox,
        "KaliBox",
        lambda: (_ for _ in ()).throw(AssertionError("constructed KaliBox")),
    )

    assert kalibox.main(args) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("[kalibox brain] usage error:")


def test_typed_brain_error_goes_to_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    error = BrainError("state_invalid", "State is invalid.", "Run update.")
    store = FakeBrainStore(error=error)
    _install_seams(monkeypatch, store)

    assert kalibox.main(["brain", "status"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == (
        "[kalibox brain] state_invalid: State is invalid. Action: Run update.\n"
    )
