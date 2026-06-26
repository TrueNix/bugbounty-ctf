"""Tests for the FTS5 knowledge base."""

from __future__ import annotations

from pathlib import Path

import pytest

from bugbounty_ctf.knowledge import KnowledgeBase


@pytest.fixture
def temp_kb(tmp_path: Path) -> KnowledgeBase:
    """Create a temporary KnowledgeBase with the project's references."""
    refs_dir = Path(__file__).parent.parent / "references"
    db_path = str(tmp_path / "test_knowledge.db")
    kb = KnowledgeBase(db_path=db_path, references_dir=str(refs_dir))
    kb.reindex()
    return kb


class TestKnowledgeBaseInit:
    def test_initializes_and_indexes(self, temp_kb: KnowledgeBase) -> None:
        docs = temp_kb.list_docs()
        assert len(docs) > 0
        assert "payload-library.md" in docs

    def test_reindex_returns_section_count(self, temp_kb: KnowledgeBase) -> None:
        count = temp_kb.reindex()
        assert count > 0


class TestSearch:
    def test_search_returns_results(self, temp_kb: KnowledgeBase) -> None:
        results = temp_kb.search("SQL injection")
        assert len(results) > 0
        assert any("snippet" in r for r in results)

    def test_search_ranks_relevant_docs_higher(self, temp_kb: KnowledgeBase) -> None:
        sqli_results = temp_kb.search("SQL injection union select")
        generic_results = temp_kb.search("asdfqwer random nonsense")
        assert len(sqli_results) > len(generic_results)

    def test_search_empty_query_returns_empty(self, temp_kb: KnowledgeBase) -> None:
        assert temp_kb.search("") == []

    def test_search_returns_snippets(self, temp_kb: KnowledgeBase) -> None:
        results = temp_kb.search("SUID docker escalation")
        assert len(results) > 0
        for r in results:
            assert "filename" in r
            assert "section" in r
            assert "snippet" in r


class TestSuggestMethodology:
    def test_suggest_for_flask_jinja(self, temp_kb: KnowledgeBase) -> None:
        results = temp_kb.suggest_methodology(["Flask/Python (Werkzeug)", "Jinja2 template engine"])
        assert len(results) > 0
        assert any("jinja" in r["matched_keywords"] or "flask" in r["matched_keywords"] for r in results)

    def test_suggest_for_nginx(self, temp_kb: KnowledgeBase) -> None:
        results = temp_kb.suggest_methodology(["nginx"])
        assert len(results) > 0

    def test_suggest_for_php(self, temp_kb: KnowledgeBase) -> None:
        results = temp_kb.suggest_methodology(["PHP"])
        assert len(results) > 0

    def test_suggest_empty_hints_returns_empty(self, temp_kb: KnowledgeBase) -> None:
        assert temp_kb.suggest_methodology([]) == []


class TestGetDoc:
    def test_get_existing_doc(self, temp_kb: KnowledgeBase) -> None:
        content = temp_kb.get_doc("payload-library.md")
        assert content is not None
        assert len(content) > 100

    def test_get_nonexistent_doc_returns_none(self, temp_kb: KnowledgeBase) -> None:
        assert temp_kb.get_doc("nonexistent.md") is None


class TestDbIsolation:
    def test_separate_db_instances(self, tmp_path: Path) -> None:
        refs_dir = Path(__file__).parent.parent / "references"
        db1 = str(tmp_path / "kb1.db")
        db2 = str(tmp_path / "kb2.db")
        kb1 = KnowledgeBase(db_path=db1, references_dir=str(refs_dir))
        kb2 = KnowledgeBase(db_path=db2, references_dir=str(refs_dir))
        assert kb1.list_docs() == kb2.list_docs()
        kb1.close()
        kb2.close()
