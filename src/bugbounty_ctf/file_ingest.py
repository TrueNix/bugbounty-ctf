from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, TypedDict

from bugbounty_ctf.extractor import IoCExtractor, format_extraction_summary
from bugbounty_ctf.knowledge import KnowledgeBase, _split_into_sections

DEFAULT_MAX_CHARS: Final = 2000
TEXT_SUFFIXES: Final = frozenset({".txt", ".md"})

logger = logging.getLogger(__name__)


class IngestSummary(TypedDict):
    files: int
    parsed: int
    added: int
    skipped_duplicates: int
    skipped: int


class PdfTextParser(Protocol):
    def __call__(self, path: Path) -> Sequence[tuple[str, str]]: ...


@dataclass(frozen=True, slots=True)
class PdfParserUnavailableError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


def ingest_files(
    paths: list[Path],
    kb: KnowledgeBase,
    parser: PdfTextParser | None = None,
    *,
    extract_iocs: bool = False,
) -> IngestSummary:
    summary = IngestSummary(files=len(paths), parsed=0, added=0, skipped_duplicates=0, skipped=0)

    for path in paths:
        sections = _sections_for_path(path, parser)
        if not sections:
            summary["skipped"] += 1
            continue

        summary["parsed"] += len(sections)
        for title, chunk in sections:
            added = kb.add_reference(
                source=f"file:{path.name}",
                title=title,
                body=chunk,
                tags="file,ingested",
                key=_stable_key(path, chunk),
            )
            if added:
                summary["added"] += 1
                if extract_iocs:
                    _add_ioc_summary(
                        kb,
                        title=title,
                        body=chunk,
                        key=f"{path.name}:{_stable_key(path, chunk)}",
                    )
            else:
                summary["skipped_duplicates"] += 1

    return summary


def _add_ioc_summary(kb: KnowledgeBase, *, title: str, body: str, key: str) -> None:
    findings = IoCExtractor().extract(body, source=key)
    summary_body = format_extraction_summary(findings)
    if not summary_body:
        return
    kb.add_reference(
        source="iocs",
        title=f"IoCs for {title}",
        body=summary_body,
        tags="ioc,ingested",
        key=key,
    )


def _extract_pdf_text(
    path: Path,
    parser: PdfTextParser | None = None,
) -> list[tuple[str, str]]:
    pdf_parser = parser if parser is not None else _default_pdf_parser
    return [(title, text.strip()) for title, text in pdf_parser(path) if text.strip()]


def _chunk_text(text: str, max_chars: int = DEFAULT_MAX_CHARS) -> list[str]:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n").strip()
    if not normalized:
        return []

    chunks: list[str] = []
    current: list[str] = []
    for paragraph in _paragraphs(normalized):
        for segment in _paragraph_segments(paragraph, max_chars):
            candidate = "\n\n".join([*current, segment]) if current else segment
            if len(candidate) <= max_chars:
                current.append(segment)
                continue
            if current:
                chunks.append("\n\n".join(current))
                current = []
            if len(segment) <= max_chars:
                current.append(segment)
            else:
                chunks.append(segment)

    if current:
        chunks.append("\n\n".join(current))
    return chunks


def _sections_for_path(
    path: Path,
    parser: PdfTextParser | None,
) -> list[tuple[str, str]]:
    suffix = path.suffix.lower()
    if suffix in TEXT_SUFFIXES:
        try:
            return _extract_text_sections(path)
        except (OSError, UnicodeError) as exc:
            logger.warning("skipping file %s: %s", path, exc)
            return []
    if suffix == ".pdf":
        try:
            return _sections_from_pdf_pages(_extract_pdf_text(path, parser))
        except PdfParserUnavailableError as exc:
            logger.warning("skipping pdf %s: %s", path, exc)
            return []
        except (OSError, RuntimeError, ValueError) as exc:
            logger.warning("skipping pdf %s: %s", path, exc)
            return []

    logger.warning("skipping unsupported file type %s", path)
    return []


def _extract_text_sections(path: Path) -> list[tuple[str, str]]:
    content = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".md":
        max_section_len = max(len(content) + 1, DEFAULT_MAX_CHARS)
        sections = _split_into_sections(content, max_section_len=max_section_len)
        return [
            titled_chunk(section["header"], chunk, index, len(chunks))
            for section in sections
            for chunks in [_chunk_text(section["body"])]
            for index, chunk in enumerate(chunks, start=1)
        ]

    chunks = _chunk_text(content)
    return [
        titled_chunk(path.stem, chunk, index, len(chunks))
        for index, chunk in enumerate(chunks, start=1)
    ]


def _sections_from_pdf_pages(pages: list[tuple[str, str]]) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    for page_title, page_text in pages:
        chunks = _chunk_text(page_text)
        sections.extend(
            titled_chunk(page_title, chunk, index, len(chunks))
            for index, chunk in enumerate(chunks, start=1)
        )
    return sections


def titled_chunk(title: str, chunk: str, index: int, total: int) -> tuple[str, str]:
    if total <= 1:
        return title, chunk
    return f"{title} (part {index})", chunk


def _default_pdf_parser(path: Path) -> list[tuple[str, str]]:
    try:
        import fitz
    except ImportError as exc:
        raise PdfParserUnavailableError(
            "PyMuPDF is not installed; install bugbounty-ctf[pdf] to ingest PDFs"
        ) from exc

    pages: list[tuple[str, str]] = []
    with fitz.open(path) as document:
        for index, page in enumerate(document, start=1):
            pages.append((f"Page {index}", str(page.get_text("text"))))
    return pages


def _paragraphs(text: str) -> list[str]:
    return [paragraph.strip() for paragraph in re.split(r"\n\s*\n+", text) if paragraph.strip()]


def _paragraph_segments(paragraph: str, max_chars: int) -> list[str]:
    if len(paragraph) <= max_chars:
        return [paragraph]

    sentences = [sentence.strip() for sentence in re.split(r"(?<=[.!?])\s+", paragraph)]
    segments: list[str] = []
    current = ""
    for sentence in sentences:
        if not sentence:
            continue
        candidate = f"{current} {sentence}".strip() if current else sentence
        if len(candidate) <= max_chars:
            current = candidate
            continue
        if current:
            segments.append(current)
        current = sentence

    if current:
        segments.append(current)
    return segments or [paragraph]


def _stable_key(path: Path, chunk: str) -> str:
    identity = f"{path.resolve(strict=False)}\n{chunk}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
