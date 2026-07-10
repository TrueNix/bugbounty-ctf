"""FTS5-backed knowledge base over reference methodology docs.

Provides full-text search across all reference walkthroughs and a
suggest_methodology() function that maps technology fingerprints to
relevant exploit methodology.

No external dependencies — uses SQLite FTS5 (Python stdlib).
"""

from __future__ import annotations

import contextlib
import json
import math
import os
import re
import sqlite3
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

Embedder = Callable[[str], Sequence[float]]


def _default_db_path() -> str:
    return os.path.expanduser("~/.hermes/knowledge.db")


def _split_into_sections(content: str, max_section_len: int = 2000) -> list[dict[str, str]]:
    """Split a markdown doc into sections by headers for better FTS granularity."""
    sections: list[dict[str, str]] = []
    current_header = "intro"
    current_body: list[str] = []

    for line in content.split("\n"):
        if line.startswith("#"):
            if current_body:
                body = "\n".join(current_body).strip()
                if body:
                    sections.append({"header": current_header, "body": body})
            current_header = line.lstrip("#").strip() or "unnamed"
            current_body = []
        else:
            current_body.append(line)

    if current_body:
        body = "\n".join(current_body).strip()
        if body:
            sections.append({"header": current_header, "body": body})

    merged: list[dict[str, str]] = []
    for s in sections:
        if len(s["body"]) > max_section_len:
            chunks = [
                s["body"][i : i + max_section_len]
                for i in range(0, len(s["body"]), max_section_len)
            ]
            for i, chunk in enumerate(chunks):
                merged.append({"header": f"{s['header']} (part {i + 1})", "body": chunk})
        else:
            merged.append(s)

    return merged


class KnowledgeBase:
    """Full-text search over reference methodology docs.

    Indexes all .md and .py files in the references/ directory at first use,
    then provides fast FTS5 search and technology-based methodology suggestions.

    Usage:
        kb = KnowledgeBase()
        results = kb.search("nginx-ui authentication bypass")
        suggestions = kb.suggest_methodology(["nginx", "Flask", "PHP"])
    """

    TECH_KEYWORDS: ClassVar[dict[str, list[str]]] = {
        "nginx": ["nginx", "reverse proxy", "upstream"],
        "Flask": ["flask", "jinja", "werkzeug", "python"],
        "Django": ["django", "sessionid", "csrftoken"],
        "PHP": ["php", "PHPSESSID", "phpinfo"],
        "Node.js": ["node", "express", "connect.sid"],
        "Java": ["java", "tomcat", "JSESSIONID", "spring"],
        "SQLite": ["sqlite", "sqlite3", "pragma"],
        "MySQL": ["mysql", "mysqli", "information_schema"],
        "PostgreSQL": ["postgres", "psql", "pg_"],
        "MongoDB": ["mongo", "mongodb", "nosql"],
        "Docker": ["docker", "container", "dockerfile"],
        "Jinja2": ["jinja", "jinja2", "{{", "template"],
    }

    def __init__(
        self,
        db_path: str | None = None,
        references_dir: str | Path | None = None,
        *,
        embedder: Embedder | None = None,
    ) -> None:
        self.db_path = db_path or _default_db_path()
        self.references_dir = str(references_dir or self._find_references_dir())
        # Optional embedding function for hybrid semantic search. When provided,
        # FTS5 supplies recall candidates and the embedder reranks them by
        # cosine similarity. Kept fully optional so the package has no ML deps.
        self.embedder = embedder
        self._conn: sqlite3.Connection | None = None
        self._init_db()
        self._index_if_empty()

    def _find_references_dir(self) -> Path:
        """Find the references/ directory relative to this package."""
        pkg_dir = Path(__file__).parent
        candidates = [
            pkg_dir / "references",
            pkg_dir.parent.parent / "references",
            Path.cwd() / "references",
        ]
        for c in candidates:
            if c.is_dir():
                return c
        return pkg_dir.parent / "references"

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _init_db(self) -> None:
        parent = os.path.dirname(self.db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS docs (
                id INTEGER PRIMARY KEY,
                filename TEXT NOT NULL,
                section TEXT NOT NULL,
                content TEXT NOT NULL,
                tags TEXT DEFAULT '',
                indexed_at TEXT
            )
        """)
        self.conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(
                filename, section, content, tags,
                content='docs', content_rowid='id'
        )
        """)
        self.conn.execute("""
            CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON docs BEGIN
                INSERT INTO docs_fts(rowid, filename, section, content, tags)
                VALUES (new.id, new.filename, new.section, new.content, new.tags);
            END
        """)
        self.conn.execute("""
            CREATE TRIGGER IF NOT EXISTS docs_ad AFTER DELETE ON docs BEGIN
                INSERT INTO docs_fts(docs_fts, rowid, filename, section, content, tags)
                VALUES('delete', old.id, old.filename, old.section, old.content, old.tags);
            END
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS doc_vectors (
                doc_id INTEGER PRIMARY KEY,
                vec TEXT NOT NULL
            )
        """)
        self.conn.commit()

    def _index_if_empty(self) -> None:
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM docs").fetchone()
        if row["cnt"] > 0:
            return
        self.reindex()

    LESSON_PREFIX = "learned::"
    INGESTED_PREFIX = "ingested::"

    def reindex(self) -> int:
        """Reindex all reference docs. Returns number of sections indexed.

        Learned lessons and ingested references are preserved — they are the
        toolkit's write-back memory and pull-based public-reference corpus, not
        part of the static hand-curated reference directory.
        """
        self.conn.execute(
            "DELETE FROM docs WHERE filename NOT LIKE ? AND filename NOT LIKE ?",
            (f"{self.LESSON_PREFIX}%", f"{self.INGESTED_PREFIX}%"),
        )
        # Re-inserted docs get fresh ids; drop cached vectors for lazy recompute.
        self.conn.execute("DELETE FROM doc_vectors")
        self.conn.commit()

        count = 0
        if not os.path.isdir(self.references_dir):
            return 0

        for filepath in sorted(Path(self.references_dir).rglob("*")):
            if filepath.suffix not in (".md", ".py", ".txt"):
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            relative_name = filepath.name
            tags = self._extract_tags(content)

            if filepath.suffix == ".md":
                sections = _split_into_sections(content)
                for section in sections:
                    self.conn.execute(
                        "INSERT INTO docs (filename, section, content, tags) VALUES (?, ?, ?, ?)",
                        (relative_name, section["header"], section["body"], tags),
                    )
                    count += 1
            else:
                self.conn.execute(
                    "INSERT INTO docs (filename, section, content, tags) VALUES (?, ?, ?, ?)",
                    (relative_name, "full", content, tags),
                )
                count += 1

        self.conn.commit()
        return count

    @staticmethod
    def _extract_tags(content: str) -> str:
        """Extract tags from markdown frontmatter or first few lines."""
        tags: list[str] = []
        match = re.search(r"tags:\s*\[(.*?)\]", content[:500])
        if match:
            tag_str = match.group(1)
            tags = [t.strip().strip('"').strip("'") for t in tag_str.split(",")]
        keywords = re.findall(
            r"\b(sqli|xss|ssti|ssrf|xxe|idor|jwt|race|deserialization|upload|docker|suid|escalation|nginx|flask|django|php|sqlite|mysql|graphql|ldap|nosql)\b",
            content[:1000],
            re.IGNORECASE,
        )
        tags.extend(keywords)
        return ", ".join(set(tags))

    def search(self, query: str, limit: int = 10) -> list[dict[str, Any]]:
        """Full-text search across all reference docs.

        Returns ranked results with filename, section, snippet, and score.
        """
        fts_query = self._build_fts_query(query)
        if not fts_query:
            return []

        # With an embedder, pull a wider FTS candidate set to rerank semantically.
        fetch = limit * 4 if self.embedder is not None else limit
        rows = self.conn.execute(
            """
            SELECT
                docs.id,
                docs.filename,
                docs.section,
                snippet(docs_fts, 2, '>>', '<<', '...', 20) as snippet,
                rank
            FROM docs_fts
            JOIN docs ON docs.id = docs_fts.rowid
            WHERE docs_fts MATCH ?
            ORDER BY rank
            LIMIT ?
            """,
            (fts_query, fetch),
        ).fetchall()

        results = [
            {
                "id": row["id"],
                "filename": row["filename"],
                "section": row["section"],
                "snippet": row["snippet"],
                "score": -row["rank"],
            }
            for row in rows
        ]

        if self.embedder is not None and results:
            results = self._semantic_rerank(query, results)

        for r in results:
            r.pop("id", None)
        return results[:limit]

    def _semantic_rerank(
        self, query: str, candidates: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Rerank FTS candidates by cosine similarity to the query embedding."""
        try:
            qv = list(self.embedder(query)) if self.embedder else []
        except Exception:
            return candidates
        if not qv:
            return candidates
        for c in candidates:
            dv = self._doc_vector(int(c["id"]))
            c["score"] = self._cosine(qv, dv)
        candidates.sort(key=lambda c: c["score"], reverse=True)
        return candidates

    def _doc_vector(self, doc_id: int) -> list[float]:
        """Return (and cache) the embedding for a doc row."""
        row = self.conn.execute(
            "SELECT vec FROM doc_vectors WHERE doc_id = ?", (doc_id,)
        ).fetchone()
        if row is not None:
            return list(json.loads(row["vec"]))
        content_row = self.conn.execute(
            "SELECT content FROM docs WHERE id = ?", (doc_id,)
        ).fetchone()
        if content_row is None or self.embedder is None:
            return []
        try:
            vec = [float(x) for x in self.embedder(content_row["content"])]
        except Exception:
            return []
        self.conn.execute(
            "INSERT OR REPLACE INTO doc_vectors (doc_id, vec) VALUES (?, ?)",
            (doc_id, json.dumps(vec)),
        )
        self.conn.commit()
        return vec

    @staticmethod
    def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
        if not a or not b or len(a) != len(b):
            return 0.0
        dot = sum(x * y for x, y in zip(a, b, strict=False))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na == 0.0 or nb == 0.0:
            return 0.0
        return dot / (na * nb)

    @staticmethod
    def _build_fts_query(query: str) -> str:
        """Convert a natural language query to an FTS5 query string."""
        tokens = re.findall(r"\w+", query.lower())
        if not tokens:
            return ""
        return " OR ".join(f'"{t}"*' for t in tokens)

    def suggest_methodology(self, tech_hints: list[str]) -> list[dict[str, Any]]:
        """Given technology fingerprints, suggest relevant methodology docs.

        Maps detected technologies to keyword searches and returns ranked docs.
        """
        all_keywords: list[str] = []
        for hint in tech_hints:
            hint_lower = hint.lower()
            for tech, keywords in self.TECH_KEYWORDS.items():
                if tech.lower() in hint_lower or any(k in hint_lower for k in keywords):
                    all_keywords.extend(keywords)

        if not all_keywords:
            return []

        unique_keywords = list(set(all_keywords))
        query = " OR ".join(f'"{k}"*' for k in unique_keywords)

        rows = self.conn.execute(
            """
            SELECT DISTINCT
                docs.filename,
                docs.section,
                snippet(docs_fts, 2, '>>', '<<', '...', 20) as snippet,
                rank
            FROM docs_fts
            JOIN docs ON docs.id = docs_fts.rowid
            WHERE docs_fts MATCH ?
            ORDER BY rank
            LIMIT 10
            """,
            (query,),
        ).fetchall()

        return [
            {
                "filename": row["filename"],
                "section": row["section"],
                "snippet": row["snippet"],
                "matched_keywords": unique_keywords,
            }
            for row in rows
        ]

    def get_doc(self, filename: str) -> str | None:
        """Retrieve a full reference doc by filename.

        Resolves the path and confirms it stays inside the references
        directory, so a ``filename`` like ``../../../etc/passwd`` (e.g. coming
        from an agent that processed attacker-controlled page content) cannot
        read files outside the doc tree.
        """
        base = Path(self.references_dir).resolve()
        try:
            path = (base / filename).resolve()
        except (OSError, ValueError):
            return None
        if not path.is_relative_to(base):
            return None
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
        return None

    def list_docs(self) -> list[str]:
        """List all indexed reference doc filenames."""
        rows = self.conn.execute("SELECT DISTINCT filename FROM docs ORDER BY filename").fetchall()
        return [row["filename"] for row in rows]

    def add_lesson(
        self, title: str, body: str, *, tags: str = "", host: str = "", key: str = ""
    ) -> bool:
        """Write a lesson learned from a confirmed finding into the knowledge base.

        Lessons are stored as ``learned::`` docs, so they are immediately
        searchable via :meth:`search`/:meth:`suggest_methodology` and survive
        :meth:`reindex`. This is the write-back half of the second-brain loop:
        future runs recall what actually worked on past targets, not just the
        static reference corpus. Returns False if an identical lesson exists.
        """
        fname = f"{self.LESSON_PREFIX}{key or host or 'general'}"
        exists = self.conn.execute(
            "SELECT 1 FROM docs WHERE filename = ? AND section = ? AND content = ? LIMIT 1",
            (fname, title, body),
        ).fetchone()
        if exists is not None:
            return False
        self.conn.execute(
            "INSERT INTO docs (filename, section, content, tags, indexed_at) VALUES (?, ?, ?, ?, ?)",
            (fname, title, body, tags, datetime.now().isoformat()),
        )
        self.conn.commit()
        return True

    @staticmethod
    def _namespace_segment(value: str) -> str:
        segment = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-._")
        return segment or "unknown"

    def add_reference(
        self,
        source: str,
        title: str,
        body: str,
        *,
        tags: str = "",
        key: str = "",
        retention_cap: int | None = None,
    ) -> bool:
        source_key = self._namespace_segment(source)
        entry_key = self._namespace_segment(key or title)
        fname = f"{self.INGESTED_PREFIX}{source_key}::{entry_key}"
        exists = self.conn.execute(
            "SELECT 1 FROM docs WHERE filename = ? AND section = ? AND content = ? LIMIT 1",
            (fname, title, body),
        ).fetchone()
        if exists is not None:
            return False
        self.conn.execute(
            "INSERT INTO docs (filename, section, content, tags, indexed_at) VALUES (?, ?, ?, ?, ?)",
            (fname, title, body, tags, datetime.now().isoformat()),
        )
        self._prune_references(retention_cap)
        self.conn.commit()
        return True

    def list_lessons(self) -> list[dict[str, str]]:
        """Return all learned lessons (write-back memory), most recent first."""
        rows = self.conn.execute(
            "SELECT filename, section, content, tags FROM docs "
            "WHERE filename LIKE ? ORDER BY indexed_at DESC",
            (f"{self.LESSON_PREFIX}%",),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_references(self, limit: int | None = None) -> list[dict[str, str]]:
        params: tuple[str] | tuple[str, int]
        query = (
            "SELECT filename, section, content, tags FROM docs "
            "WHERE filename LIKE ? ORDER BY indexed_at DESC"
        )
        if limit is None:
            params = (f"{self.INGESTED_PREFIX}%",)
        else:
            query = f"{query} LIMIT ?"
            params = (f"{self.INGESTED_PREFIX}%", limit)
        rows = self.conn.execute(query, params).fetchall()
        return [
            {
                "filename": str(row["filename"]),
                "section": str(row["section"]),
                "content": str(row["content"]),
                "tags": str(row["tags"]),
            }
            for row in rows
        ]

    def _prune_references(self, retention_cap: int | None) -> None:
        if retention_cap is None or retention_cap < 1:
            return
        self.conn.execute(
            """
            DELETE FROM docs
            WHERE id IN (
                SELECT id FROM docs
                WHERE filename LIKE ?
                ORDER BY indexed_at DESC, id DESC
                LIMIT -1 OFFSET ?
            )
            """,
            (f"{self.INGESTED_PREFIX}%", retention_cap),
        )

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> KnowledgeBase:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def __del__(self) -> None:
        # Best-effort cleanup so a KnowledgeBase that outlives its caller does
        # not leak the SQLite connection (most callers never call close()).
        with contextlib.suppress(Exception):
            self.close()
