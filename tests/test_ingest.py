from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from bugbounty_ctf.knowledge import KnowledgeBase

_REFS = Path(__file__).parent.parent / "references"


class FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text

    def raise_for_status(self) -> None:
        return None


def _kb(tmp_path: Path) -> KnowledgeBase:
    return KnowledgeBase(db_path=str(tmp_path / "kb.db"), references_dir=str(_REFS))


def _fetcher(feeds: dict[str, str]) -> Callable[[str], FakeResponse]:
    def fetch(url: str) -> FakeResponse:
        if url not in feeds:
            raise OSError(f"dead feed: {url}")
        return FakeResponse(feeds[url])

    return fetch


RSS_FEED = """<?xml version="1.0" encoding="UTF-8" ?>
<rss version="2.0">
  <channel>
    <title>Example CTF Writeups</title>
    <item>
      <title>Widget Shop SQLi Writeup</title>
      <link>https://ctf.example/writeups/widget-shop-sqli</link>
      <pubDate>Mon, 01 Jul 2024 07:00:00 GMT</pubDate>
      <description><![CDATA[<p>Union SQL injection found with <b>marker_rss_sqli</b>.</p>]]></description>
    </item>
    <item>
      <title>Skipped by limit</title>
      <link>https://ctf.example/writeups/skipped</link>
      <description>limit marker should not appear</description>
    </item>
  </channel>
</rss>
"""

ATOM_FEED = """<?xml version="1.0" encoding="UTF-8" ?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Example AppSec Blog</title>
  <entry>
    <title>Blind SSRF Through PDF Renderer</title>
    <link href="https://blog.example/blind-ssrf-pdf" />
    <updated>2024-07-02T12:00:00Z</updated>
    <summary type="html">&lt;p&gt;OAST callback marker_atom_ssrf confirms impact.&lt;/p&gt;</summary>
  </entry>
</feed>
"""


def test_parses_rss_entries_into_reference_docs(tmp_path: Path) -> None:
    from bugbounty_ctf.ingest import ingest_writeups

    kb = _kb(tmp_path)
    summary = ingest_writeups(
        feeds=["https://ctftime.example/writeups.xml"],
        kb=kb,
        fetcher=_fetcher({"https://ctftime.example/writeups.xml": RSS_FEED}),
        limit=1,
    )

    assert summary == {"feeds": 1, "fetched": 1, "added": 1, "skipped_duplicates": 0}
    refs = kb.list_references()
    assert len(refs) == 1
    assert refs[0]["section"] == "Widget Shop SQLi Writeup"
    assert refs[0]["filename"].startswith("ingested::ctftime.example::")
    assert "Source feed: https://ctftime.example/writeups.xml" in refs[0]["content"]
    assert "marker_rss_sqli" in refs[0]["content"]
    assert all("limit marker" not in ref["content"] for ref in refs)
    kb.close()


def test_parses_atom_feed(tmp_path: Path) -> None:
    from bugbounty_ctf.ingest import ingest_writeups

    kb = _kb(tmp_path)
    summary = ingest_writeups(
        feeds=["https://blog.example/feed.atom"],
        kb=kb,
        fetcher=_fetcher({"https://blog.example/feed.atom": ATOM_FEED}),
    )

    assert summary["added"] == 1
    assert any("marker_atom_ssrf" in ref["content"] for ref in kb.list_references())
    kb.close()


def test_html_stripped_from_summary() -> None:
    from bugbounty_ctf.ingest import _strip_html

    assert _strip_html("<p>Alpha <b>beta</b>&amp; gamma</p>") == "Alpha beta & gamma"


def test_idempotent_reingest_dedupes(tmp_path: Path) -> None:
    from bugbounty_ctf.ingest import ingest_writeups

    kb = _kb(tmp_path)
    fetcher = _fetcher({"https://ctftime.example/writeups.xml": RSS_FEED})

    first = ingest_writeups(feeds=["https://ctftime.example/writeups.xml"], kb=kb, fetcher=fetcher)
    second = ingest_writeups(feeds=["https://ctftime.example/writeups.xml"], kb=kb, fetcher=fetcher)

    assert first == {"feeds": 1, "fetched": 2, "added": 2, "skipped_duplicates": 0}
    assert second == {"feeds": 1, "fetched": 2, "added": 0, "skipped_duplicates": 2}
    assert len(kb.list_references()) == 2
    kb.close()


def test_dead_feed_skipped_without_aborting_batch(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    from bugbounty_ctf.ingest import ingest_writeups

    kb = _kb(tmp_path)
    summary = ingest_writeups(
        feeds=["https://dead.example/feed.xml", "https://blog.example/feed.atom"],
        kb=kb,
        fetcher=_fetcher({"https://blog.example/feed.atom": ATOM_FEED}),
    )

    assert summary == {"feeds": 2, "fetched": 1, "added": 1, "skipped_duplicates": 0}
    assert "skipping feed https://dead.example/feed.xml" in caplog.text
    assert any("marker_atom_ssrf" in ref["content"] for ref in kb.list_references())
    kb.close()


def test_reindex_preserves_ingested_docs(tmp_path: Path) -> None:
    kb = _kb(tmp_path)
    assert kb.add_reference(
        source="example.org",
        title="Preserved writeup",
        body="body persist_ingested_marker",
        tags="writeup,ingested",
        key="preserved",
    )

    kb.reindex()

    assert any("persist_ingested_marker" in ref["content"] for ref in kb.list_references())
    kb.close()


def test_ingested_docs_are_searchable(tmp_path: Path) -> None:
    kb = _kb(tmp_path)
    assert kb.add_reference(
        source="example.org",
        title="GraphQL batching advisory",
        body="Unique searchable marker_graphql_batching technique",
        tags="writeup,ingested",
        key="graphql-batching",
    )

    results = kb.search("marker_graphql_batching")

    assert any(result["filename"].startswith("ingested::") for result in results)
    kb.close()


def test_ingest_attack_techniques(tmp_path: Path) -> None:
    from bugbounty_ctf.ingest import MITRE_FEEDS, ingest_attack_techniques

    attack_json = """
    {
      "type": "bundle",
      "objects": [
        {
          "type": "attack-pattern",
          "id": "attack-pattern--11111111-1111-4111-8111-111111111111",
          "name": "Command and Scripting Interpreter",
          "description": "Adversaries may abuse command interpreters for marker_attack_t1059.",
          "external_references": [
            {
              "source_name": "mitre-attack",
              "external_id": "T1059",
              "url": "https://attack.mitre.org/techniques/T1059/"
            }
          ],
          "kill_chain_phases": [
            {
              "kill_chain_name": "mitre-attack",
              "phase_name": "execution"
            },
            {
              "kill_chain_name": "mitre-attack",
              "phase_name": "defense-evasion"
            }
          ],
          "x_mitre_platforms": ["Linux", "Windows"]
        },
        {
          "type": "malware",
          "name": "Not a technique"
        }
      ]
    }
    """
    kb = _kb(tmp_path)
    fetcher = _fetcher({MITRE_FEEDS[0]: attack_json})

    first = ingest_attack_techniques(kb=kb, fetcher=fetcher)
    second = ingest_attack_techniques(kb=kb, fetcher=fetcher)

    assert first == {"feeds": 1, "fetched": 1, "added": 1, "skipped_duplicates": 0}
    assert second == {"feeds": 1, "fetched": 1, "added": 0, "skipped_duplicates": 1}
    refs = kb.list_references()
    assert len(refs) == 1
    assert refs[0]["filename"] == "ingested::attack::t1059"
    assert refs[0]["section"] == "T1059 Command and Scripting Interpreter"
    assert "Description: Adversaries may abuse command interpreters" in refs[0]["content"]
    assert "Tactics: defense-evasion, execution" in refs[0]["content"]
    assert "Platforms: Linux, Windows" in refs[0]["content"]
    assert "marker_attack_t1059" in refs[0]["content"]
    assert any("T1059" in result["section"] for result in kb.search("marker_attack_t1059"))
    kb.close()
