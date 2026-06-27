"""Tests for the second-brain loop: DB recall/dedup and KB write-back."""

from __future__ import annotations

from pathlib import Path

from bugbounty_ctf.engine import ScannerDB
from bugbounty_ctf.knowledge import KnowledgeBase

_REFS = Path(__file__).parent.parent / "references"


class TestFindingDedup:
    def test_repeated_finding_is_deduped(self) -> None:
        db = ScannerDB(":memory:")
        for _ in range(3):
            db.save_finding("host.test", "/login", "sqli", payload="'", confidence=0.8)
        rows = db.findings_for_host("host.test")
        assert len(rows) == 1

    def test_distinct_findings_kept(self) -> None:
        db = ScannerDB(":memory:")
        db.save_finding("host.test", "/login", "sqli", payload="'")
        db.save_finding("host.test", "/login", "xss", payload="<s>")
        db.save_finding("host.test", "/search", "sqli", payload="'")
        assert len(db.findings_for_host("host.test")) == 3

    def test_repeat_refreshes_confidence(self) -> None:
        db = ScannerDB(":memory:")
        db.save_finding("h", "/x", "sqli", payload="'", confidence=0.2)
        db.save_finding("h", "/x", "sqli", payload="'", confidence=0.9)
        rows = db.findings_for_host("h")
        assert len(rows) == 1
        assert rows[0]["confidence"] == 0.9

    def test_recall_is_scoped_to_host(self) -> None:
        db = ScannerDB(":memory:")
        db.save_finding("a.test", "/x", "sqli")
        db.save_finding("b.test", "/y", "xss")
        assert len(db.findings_for_host("a.test")) == 1
        assert db.findings_for_host("a.test")[0]["vuln_type"] == "sqli"


class TestKnowledgeWriteBack:
    def _kb(self, tmp_path: Path) -> KnowledgeBase:
        return KnowledgeBase(db_path=str(tmp_path / "kb.db"), references_dir=str(_REFS))

    def test_lesson_is_searchable(self, tmp_path: Path) -> None:
        kb = self._kb(tmp_path)
        kb.add_lesson(
            "sqli on shop.test /login",
            "Confirmed sqli. payload ' triggered marker_zqx error.",
            tags="sqli",
            host="shop.test",
        )
        results = kb.search("marker_zqx")
        assert any(r["filename"].startswith("learned::") for r in results)
        kb.close()

    def test_lesson_survives_reindex(self, tmp_path: Path) -> None:
        kb = self._kb(tmp_path)
        kb.add_lesson("t", "body persist_marker_42", host="h")
        kb.reindex()  # rebuilds the static corpus; lessons must remain
        assert any("persist_marker_42" in lesson["content"] for lesson in kb.list_lessons())
        kb.close()

    def test_lesson_dedup(self, tmp_path: Path) -> None:
        kb = self._kb(tmp_path)
        assert kb.add_lesson("title", "body", host="h") is True
        assert kb.add_lesson("title", "body", host="h") is False
        assert len(kb.list_lessons()) == 1
        kb.close()

    def test_reindex_still_loads_static_docs(self, tmp_path: Path) -> None:
        kb = self._kb(tmp_path)
        kb.add_lesson("t", "b", host="h")
        count = kb.reindex()
        assert count > 0  # reference corpus still indexed alongside lessons
        kb.close()
