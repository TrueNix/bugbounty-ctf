from __future__ import annotations

import builtins
from pathlib import Path

from bugbounty_ctf.knowledge import KnowledgeBase


def _values_by_type(text: str, type_name: str) -> list[str]:
    from bugbounty_ctf.extractor import IoCExtractor, IoCType

    extractor = IoCExtractor()
    target_type = IoCType[type_name]
    return sorted(item.value for item in extractor.extract(text) if item.type is target_type)


def _kb(tmp_path: Path) -> KnowledgeBase:
    refs = tmp_path / "refs"
    refs.mkdir(parents=True)
    return KnowledgeBase(db_path=str(tmp_path / "kb.db"), references_dir=str(refs))


def test_extract_cves_from_text() -> None:
    values = _values_by_type(
        "CVE-2025-3248 and CVE-2026-7664 mentioned during triage.",
        "CVE",
    )

    assert values == ["CVE-2025-3248", "CVE-2026-7664"]


def test_extract_ips_validates_format() -> None:
    values = _values_by_type("Target 10.10.10.5 answered; 999.1.1.1 is invalid.", "IP")

    assert values == ["10.10.10.5"]


def test_extract_hashes_md5_sha1_sha256() -> None:
    values = _values_by_type(
        "MD5 d41d8cd98f00b204e9800998ecf8427e "
        "SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709 "
        "SHA256 e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855",
        "HASH",
    )

    assert values == [
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ]


def test_extract_urls_and_emails() -> None:
    text = "Reach admin@example.htb through https://app.example.htb/login?next=/admin."

    assert _values_by_type(text, "URL") == ["https://app.example.htb/login?next=/admin"]
    assert _values_by_type(text, "EMAIL") == ["admin@example.htb"]


def test_extract_tools_keyword_match() -> None:
    values = _values_by_type("The operator used linpeas for privesc.", "TOOL")

    assert values == ["linpeas"]


def test_extract_techniques_attack_ids() -> None:
    values = _values_by_type("Observed T1059.001 during command execution.", "TECHNIQUE")

    assert values == ["T1059.001"]


def test_extract_credentials_flags_patterns() -> None:
    from bugbounty_ctf.extractor import IoCExtractor, IoCType

    findings = IoCExtractor().extract("Config leaked password=letmein in the debug panel.")
    credential_values = [item.value for item in findings if item.type is IoCType.CREDENTIAL_PATTERN]

    assert credential_values == ["password=***"]
    assert "letmein" not in credential_values[0]


def test_extract_dedupes_by_type_and_value() -> None:
    values = _values_by_type("CVE-2025-3248 then CVE-2025-3248 again.", "CVE")

    assert values == ["CVE-2025-3248"]


def test_extract_from_kb_iterates_ingested_docs(tmp_path: Path) -> None:
    from bugbounty_ctf.extractor import IoCType, extract_from_kb

    kb = _kb(tmp_path)
    assert kb.add_reference(
        source="writeup",
        title="One",
        body="First doc has CVE-2025-3248.",
        tags="ingested",
        key="one",
    )
    assert kb.add_reference(
        source="writeup",
        title="Two",
        body="Second doc used linpeas.",
        tags="ingested",
        key="two",
    )

    results = extract_from_kb(kb)

    assert set(results) == {"ingested::writeup::one", "ingested::writeup::two"}
    assert [item.value for item in results["ingested::writeup::one"]] == ["CVE-2025-3248"]
    assert [
        item.value for item in results["ingested::writeup::two"] if item.type is IoCType.TOOL
    ] == ["linpeas"]
    kb.close()


def test_summarize_extractions_groups_by_type() -> None:
    from bugbounty_ctf.extractor import IoCExtractor, IoCType, summarize_extractions

    summary = summarize_extractions(
        IoCExtractor().extract("CVE-2025-3248, nmap, and CVE-2025-3248.")
    )

    assert summary == {IoCType.CVE: ["CVE-2025-3248"], IoCType.TOOL: ["nmap"]}


def test_spacy_backend_skipped_gracefully_when_unavailable(monkeypatch) -> None:
    from bugbounty_ctf.extractor import IoCExtractor

    real_import = builtins.__import__

    def fake_import(
        name: str,
        globals=None,
        locals=None,
        fromlist=(),
        level: int = 0,
    ):
        if name == "spacy":
            raise ImportError("no spacy")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    findings = IoCExtractor(spacy_model="offline-model").extract("CVE-2025-3248 via nmap")

    assert [item.value for item in findings] == ["CVE-2025-3248", "nmap"]


def test_extract_iocs_opt_in_to_ingest(tmp_path: Path) -> None:
    from bugbounty_ctf.ingest import ingest_writeups

    class FakeResponse:
        text = """<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
  <channel>
    <item>
      <title>IoC Writeup</title>
      <link>https://ctf.example/ioc-writeup</link>
      <description>CVE-2025-3248 exploited with linpeas password=letmein.</description>
    </item>
  </channel>
</rss>
"""

        def raise_for_status(self) -> None:
            return None

    def fetcher(_url: str) -> FakeResponse:
        return FakeResponse()

    kb_without_iocs = _kb(tmp_path / "off")
    ingest_writeups(
        feeds=["https://ctf.example/rss"],
        kb=kb_without_iocs,
        fetcher=fetcher,
        extract_iocs=False,
    )

    assert not any(
        ref["filename"].startswith("ingested::iocs::") for ref in kb_without_iocs.list_references()
    )
    kb_without_iocs.close()

    kb_with_iocs = _kb(tmp_path / "on")
    ingest_writeups(
        feeds=["https://ctf.example/rss"],
        kb=kb_with_iocs,
        fetcher=fetcher,
        extract_iocs=True,
    )

    refs = kb_with_iocs.list_references()
    summary_refs = [ref for ref in refs if ref["filename"].startswith("ingested::iocs::")]
    assert len(summary_refs) == 1
    assert "CVE: CVE-2025-3248" in summary_refs[0]["content"]
    assert "TOOL: linpeas" in summary_refs[0]["content"]
    assert "CREDENTIAL_PATTERN: password=***" in summary_refs[0]["content"]
    assert "letmein" not in summary_refs[0]["content"]
    assert any(
        result["filename"].startswith("ingested::iocs::")
        for result in kb_with_iocs.search("CVE-2025-3248")
    )
    kb_with_iocs.close()
