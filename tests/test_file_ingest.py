from __future__ import annotations

import builtins
from pathlib import Path

from bugbounty_ctf.knowledge import KnowledgeBase


def _kb(tmp_path: Path) -> KnowledgeBase:
    refs = tmp_path / "refs"
    refs.mkdir()
    return KnowledgeBase(db_path=str(tmp_path / "kb.db"), references_dir=str(refs))


def test_ingest_txt_file(tmp_path: Path) -> None:
    from bugbounty_ctf.file_ingest import ingest_files

    kb = _kb(tmp_path)
    source = tmp_path / "report.txt"
    source.write_text(
        "Privilege escalation notes\n\nUnique marker_file_txt_ingest via writable cron.",
        encoding="utf-8",
    )

    summary = ingest_files([source], kb)

    assert summary == {
        "files": 1,
        "parsed": 1,
        "added": 1,
        "skipped_duplicates": 0,
        "skipped": 0,
    }
    refs = kb.list_references()
    assert refs[0]["section"] == "report"
    assert refs[0]["filename"].startswith("ingested::file-report.txt::")
    assert "marker_file_txt_ingest" in refs[0]["content"]
    assert any(
        result["filename"].startswith("ingested::")
        for result in kb.search("marker_file_txt_ingest")
    )
    kb.close()


def test_ingest_pdf_uses_injected_parser(tmp_path: Path) -> None:
    from bugbounty_ctf.file_ingest import ingest_files

    kb = _kb(tmp_path)
    source = tmp_path / "playbook.pdf"
    source.write_bytes(b"%PDF-1.7 fake")
    parsed_paths: list[Path] = []

    def parser(path: Path) -> list[tuple[str, str]]:
        parsed_paths.append(path)
        return [
            ("Page 1", "PDF marker_file_pdf_ingest blind SSRF."),
            ("Page 2", "Second page with deserialization."),
        ]

    first = ingest_files([source], kb, parser)
    second = ingest_files([source], kb, parser)

    assert parsed_paths == [source, source]
    assert first == {
        "files": 1,
        "parsed": 2,
        "added": 2,
        "skipped_duplicates": 0,
        "skipped": 0,
    }
    assert second == {
        "files": 1,
        "parsed": 2,
        "added": 0,
        "skipped_duplicates": 2,
        "skipped": 0,
    }
    assert len(kb.list_references()) == 2
    assert any(result["section"] == "Page 1" for result in kb.search("marker_file_pdf_ingest"))
    kb.close()


def test_pdf_skipped_gracefully_when_pymupdf_absent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from bugbounty_ctf.file_ingest import ingest_files

    kb = _kb(tmp_path)
    source = tmp_path / "missing-parser.pdf"
    source.write_bytes(b"%PDF-1.7 fake")
    real_import = builtins.__import__

    def fake_import(
        name: str,
        globals=None,
        locals=None,
        fromlist=(),
        level: int = 0,
    ):
        if name == "fitz":
            raise ImportError("no pymupdf")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    summary = ingest_files([source], kb)

    assert summary == {
        "files": 1,
        "parsed": 0,
        "added": 0,
        "skipped_duplicates": 0,
        "skipped": 1,
    }
    assert kb.list_references() == []
    kb.close()


def test_chunking_splits_long_text_at_paragraph_boundaries() -> None:
    from bugbounty_ctf.file_ingest import _chunk_text

    chunks = _chunk_text(
        "Alpha paragraph stays together.\n\n"
        "Beta paragraph stays together.\n\n"
        "Gamma paragraph stays together.",
        max_chars=40,
    )

    assert chunks == [
        "Alpha paragraph stays together.",
        "Beta paragraph stays together.",
        "Gamma paragraph stays together.",
    ]


def test_ingest_files_idempotent(tmp_path: Path) -> None:
    from bugbounty_ctf.file_ingest import ingest_files

    kb = _kb(tmp_path)
    source = tmp_path / "idempotent.md"
    source.write_text(
        "# Findings\n\nUnique marker_file_idempotent report section.",
        encoding="utf-8",
    )

    first = ingest_files([source], kb)
    second = ingest_files([source], kb)

    assert first["added"] == 1
    assert first["skipped_duplicates"] == 0
    assert second["added"] == 0
    assert second["skipped_duplicates"] == 1
    assert len(kb.list_references()) == 1
    kb.close()
