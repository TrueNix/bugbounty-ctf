"""Tests for the second-brain loop: DB recall/dedup and KB write-back."""

from __future__ import annotations

from pathlib import Path

from bugbounty_ctf.engine import (
    ScannerDB,
    SecurityScanner,
    bypass_url_filter,
    get_aws_credentials,
)
from bugbounty_ctf.hypothesis import Hypothesis, HypothesisEngine
from bugbounty_ctf.knowledge import KnowledgeBase
from bugbounty_ctf.observations import ObservationStore

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


# A tiny deterministic embedder over a fixed vocabulary — no ML deps.
_VOCAB = ["sqli", "ssrf", "xss", "jwt", "nginx", "docker", "redis", "flag"]


def _fake_embed(text: str) -> list[float]:
    t = text.lower()
    return [float(t.count(w)) for w in _VOCAB]


class TestSemanticSearch:
    def _kb(self, tmp_path: Path) -> KnowledgeBase:
        return KnowledgeBase(
            db_path=str(tmp_path / "kb.db"), references_dir=str(_REFS), embedder=_fake_embed
        )

    def test_embedder_reranks_candidates(self, tmp_path: Path) -> None:
        kb = self._kb(tmp_path)
        # Both share a rare token so FTS returns both; embeddings should put the
        # sqli lesson above the ssrf one for an sqli query.
        kb.add_lesson("A", "ztoken sqli sqli sqli", host="a")
        kb.add_lesson("B", "ztoken ssrf ssrf ssrf", host="b")
        results = kb.search("sqli ztoken", limit=50)
        names = [r["filename"] for r in results]
        assert "learned::a" in names and "learned::b" in names
        assert names.index("learned::a") < names.index("learned::b")
        kb.close()

    def test_results_have_no_internal_id(self, tmp_path: Path) -> None:
        kb = self._kb(tmp_path)
        kb.add_lesson("A", "ztoken sqli", host="a")
        results = kb.search("sqli ztoken", limit=10)
        assert results and all("id" not in r for r in results)
        kb.close()

    def test_no_embedder_still_works(self, tmp_path: Path) -> None:
        kb = KnowledgeBase(db_path=str(tmp_path / "kb.db"), references_dir=str(_REFS))
        kb.add_lesson("A", "ztoken sqli", host="a")
        assert kb.search("sqli ztoken")
        kb.close()


class TestDurableReasoning:
    def test_observation_store_persists_and_reloads(self) -> None:
        db = ScannerDB(":memory:")
        store = ObservationStore(db=db, target_host="h.test")
        store.add_finding("/login", "sqli", payload="'", indicators=["x"], confidence=0.8)
        assert db.query_observations("h.test")
        # A fresh store hydrates the prior reasoning from the DB.
        reloaded = ObservationStore(db=db, target_host="h.test")
        assert reloaded.load_from_db() == 1
        assert reloaded.observations[0].vuln_type == "sqli"

    def test_hypothesis_persisted_and_recalled(self) -> None:
        scanner = SecurityScanner("http://h.test/", db=ScannerDB(":memory:"))
        engine = HypothesisEngine(scanner)
        engine._persist(
            Hypothesis(vuln_type="sqli", endpoint="/x", param="id", confidence=0.9, confirmed=True)
        )
        prior = engine.load_prior(status="confirmed")
        assert any(p["vuln_type"] == "sqli" for p in prior)

    def test_observations_query_filters_confidence(self) -> None:
        db = ScannerDB(":memory:")
        db.save_observation("h", {"vuln_type": "sqli", "endpoint": "/a", "confidence": 0.9})
        db.save_observation("h", {"vuln_type": "xss", "endpoint": "/b", "confidence": 0.2})
        assert len(db.query_observations("h", min_confidence=0.5)) == 1


class TestRetentionAndProvenance:
    def test_prune_history_keeps_recent(self) -> None:
        db = ScannerDB(":memory:")
        for i in range(10):
            db.save_history("h.test", "/x", "GET", f"p{i}", False)
        deleted = db.prune_history("h.test", keep=3)
        assert deleted == 7
        assert len(db.query_history("target_host = ?", ("h.test",))) == 3

    def test_finding_records_provenance(self) -> None:
        db = ScannerDB(":memory:")
        db.save_finding("h.test", "/login", "sqli", payload="'", source="playbook.md")
        rows = db.findings_for_host("h.test")
        assert rows[0]["source"] == "playbook.md"

    def test_migration_is_idempotent(self, tmp_path: Path) -> None:
        p = str(tmp_path / "m.db")
        ScannerDB(p).close()
        db2 = ScannerDB(p)  # re-open: _migrate must not error or duplicate the column
        db2.save_finding("h", "/x", "sqli", payload="'", source="s")
        assert db2.findings_for_host("h")[0]["source"] == "s"


class _Resp:
    def __init__(self, text: str) -> None:
        self.text = text
        self.status_code = 200


class TestCloudFindingRecording:
    """SSRF→AWS wins must land in the findings DB (regression: previously the
    metadata/credential helpers returned data but recorded nothing)."""

    def test_get_aws_credentials_records_finding(self) -> None:
        sc = SecurityScanner("http://t.test/", db=ScannerDB(":memory:"))
        responses = [
            _Resp("<pre>nimbus-web-role</pre>"),  # role listing
            _Resp('<pre>{"AccessKeyId": "ASIA123", "SecretAccessKey": "x", "Token": "y"}</pre>'),
        ]

        it = iter(responses)
        sc._make_request = lambda *a, **k: next(it)  # type: ignore[method-assign,assignment]
        # SSRF sink is passed explicitly (generic API — no hardcoded endpoint).
        creds = get_aws_credentials(sc, ssrf_endpoint="http://t.test/fetch")
        assert creds and creds["AccessKeyId"] == "ASIA123"
        assert any(f["type"] == "ssrf_aws_credentials" for f in sc.findings)
        assert sc.db.findings_for_host(sc.target_identity)  # persisted

    def test_bypass_url_filter_records_finding(self) -> None:
        sc = SecurityScanner("http://t.test/", db=ScannerDB(":memory:"))
        sc._make_request = lambda *a, **k: _Resp("Fetched: ok")  # type: ignore[method-assign,assignment]
        out = bypass_url_filter("http://t.test/x", sc, ssrf_endpoint="http://t.test/fetch")
        assert out is not None
        assert any(f["type"] == "ssrf_filter_bypass" for f in sc.findings)


class TestSsrfDiscovery:
    """The SSRF sink must be discovered from the surface, never hardcoded."""

    def test_find_ssrf_endpoints_flags_url_params(self) -> None:
        from bugbounty_ctf.engine import find_ssrf_endpoints

        sc = SecurityScanner("http://t.test/", db=ScannerDB(":memory:"))
        # Seed a mapped surface with a URL-accepting form and a benign one.
        sc.attack_surface["/"] = {
            "forms": [
                {
                    "action": "http://t.test/fetch",
                    "method": "POST",
                    "inputs": [{"name": "url", "type": "url"}],
                },
                {
                    "action": "http://t.test/login",
                    "method": "POST",
                    "inputs": [{"name": "username", "type": "text"}],
                },
            ]
        }
        sinks = find_ssrf_endpoints(sc)
        assert {"url": "http://t.test/fetch", "method": "POST", "param": "url"} in sinks
        assert all(s["url"] != "http://t.test/login" for s in sinks)
