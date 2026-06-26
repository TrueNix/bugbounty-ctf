"""FTS5-backed knowledge base over reference methodology docs.

Provides full-text search across all reference walkthroughs and a
suggest_methodology() function that maps technology fingerprints to
relevant exploit methodology.

No external dependencies — uses SQLite FTS5 (Python stdlib).
"""

from __future__ import annotations

import os
import re
import sqlite3
from pathlib import Path
from typing import Any, ClassVar


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
        self, db_path: str | None = None, references_dir: str | Path | None = None
    ) -> None:
        self.db_path = db_path or _default_db_path()
        self.references_dir = str(references_dir or self._find_references_dir())
        self._conn: sqlite3.Connection | None = None
        self._init_db()
        self._index_if_empty()

    def _find_references_dir(self) -> Path:
        """Find the references/ directory relative to this package."""
        pkg_dir = Path(__file__).parent
        candidates = [
            pkg_dir.parent / "references",
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
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
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
        self.conn.commit()

    def _index_if_empty(self) -> None:
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM docs").fetchone()
        if row["cnt"] > 0:
            return
        self.reindex()

    def reindex(self) -> int:
        """Reindex all reference docs. Returns number of sections indexed."""
        self.conn.execute("DELETE FROM docs")
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
            (fts_query, limit),
        ).fetchall()

        return [
            {
                "filename": row["filename"],
                "section": row["section"],
                "snippet": row["snippet"],
                "score": -row["rank"],
            }
            for row in rows
        ]

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
        """Retrieve a full reference doc by filename."""
        path = Path(self.references_dir) / filename
        if path.exists():
            return path.read_text(encoding="utf-8", errors="replace")
        return None

    def list_docs(self) -> list[str]:
        """List all indexed reference doc filenames."""
        rows = self.conn.execute("SELECT DISTINCT filename FROM docs ORDER BY filename").fetchall()
        return [row["filename"] for row in rows]

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
