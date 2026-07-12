"""Write-back pattern recall in KnowledgeBase: record techniques, recall by stack."""

from __future__ import annotations

from pathlib import Path

from bugbounty_ctf.knowledge import KnowledgeBase


def _kb(tmp_path: Path) -> KnowledgeBase:
    refs = tmp_path / "refs"
    refs.mkdir()
    return KnowledgeBase(db_path=str(tmp_path / "k.db"), references_dir=refs)


def test_record_pattern_deduplicates(tmp_path: Path) -> None:
    kb = _kb(tmp_path)
    assert kb.record_pattern("ssti", "jinja sandbox escape", ["Flask", "Jinja2"]) is True
    # Same technique + same normalized stack (order/case-insensitive) is a duplicate.
    assert kb.record_pattern("ssti", "jinja sandbox escape", ["jinja2", "flask"]) is False


def test_match_patterns_by_tech_stack_overlap(tmp_path: Path) -> None:
    kb = _kb(tmp_path)
    kb.record_pattern("ssti", "jinja sandbox escape", ["Flask", "Jinja2"])
    kb.record_pattern("idor", "sequential id swap", ["Django", "PostgreSQL"])

    assert len(kb.match_patterns(tech_stack=["flask"])) == 1
    assert kb.match_patterns(tech_stack=["django"])[0]["vuln_class"] == "idor"
    assert kb.match_patterns(tech_stack=["nodejs"]) == []


def test_match_patterns_ranked_by_payout(tmp_path: Path) -> None:
    kb = _kb(tmp_path)
    kb.record_pattern("xss", "reflected", ["flask"], payout=100)
    kb.record_pattern("xss", "csp bypass", ["flask"], payout=900)

    ranked = kb.match_patterns(tech_stack=["flask"])
    assert [p["payout"] for p in ranked] == [900, 100]


def test_match_patterns_vuln_class_filter(tmp_path: Path) -> None:
    kb = _kb(tmp_path)
    kb.record_pattern("ssti", "t1", ["flask"])
    kb.record_pattern("idor", "t2", ["flask"])

    matched = kb.match_patterns(vuln_class="idor")
    assert len(matched) == 1
    assert matched[0]["technique"] == "t2"


def test_suggest_methodology_surfaces_patterns_first(tmp_path: Path) -> None:
    kb = _kb(tmp_path)
    kb.record_pattern("ssti", "jinja sandbox escape", ["Flask", "Jinja2"], payout=500)

    results = kb.suggest_methodology(["Flask/Python (Werkzeug)"])

    assert results  # a learned pattern surfaces even with no reference corpus indexed
    assert results[0]["source"] == "pattern"
    assert "flask" in results[0]["matched_keywords"]
    # Shape-compatible with reference entries so existing consumers do not break.
    assert {"filename", "section", "snippet", "matched_keywords"} <= set(results[0])


def test_suggest_methodology_empty_hints_returns_empty(tmp_path: Path) -> None:
    kb = _kb(tmp_path)
    kb.record_pattern("ssti", "t", ["flask"])
    assert kb.suggest_methodology([]) == []
