# Reference knowledge base (seed memory)

`reference_knowledge.db` is a **prebuilt, secret-free** SQLite FTS5 index of the
`references/*.md` methodology corpus. It ships with the repo so a fresh clone has
the second-brain's *reference* half ready immediately, without waiting for the
first run to index the docs.

## What it is (and is NOT)

- **IS:** an FTS index of the committed reference walkthroughs (225 docs). Every
  row corresponds to a section of a file already public in `references/`.
- **IS NOT:** engagement memory. It contains **zero** `learned::` lessons, zero
  dead-ends, zero findings, zero patterns, zero observations, zero embeddings.

This distinction is the whole security model:

| Memory kind | Where it lives | Committed? |
|:------------|:---------------|:-----------|
| Reference index (this file) | `data/reference_knowledge.db` | **Yes** (curated, safe) |
| Engagement memory (findings, dead-ends, harvested secrets) | `~/.hermes/knowledge.db` + ScannerDB | **Never** (gitignored) |

`.gitignore` blocks `knowledge.db` / `scanner.db` everywhere and force-allows
**only** this one curated file (`!data/reference_knowledge.db`). Real target data
never reaches the repo.

## Using it as a seed

```python
import shutil, os
from bugbounty_ctf.knowledge import KnowledgeBase

# Option A: point a KnowledgeBase straight at the shipped reference index (read-only use)
kb = KnowledgeBase(db_path="data/reference_knowledge.db")
print(len(kb.search("nfs")))

# Option B: seed your local runtime KB from it, then let engagement memory accrue there
runtime = os.path.expanduser("~/.hermes/knowledge.db")
if not os.path.exists(runtime):
    os.makedirs(os.path.dirname(runtime), exist_ok=True)
    shutil.copy("data/reference_knowledge.db", runtime)
kb = KnowledgeBase()  # defaults to ~/.hermes/knowledge.db — now pre-seeded
```

## Regenerating it (keep it secret-free)

Rebuild from the reference corpus only — never from a db that has seen a live
engagement:

```python
from bugbounty_ctf.knowledge import KnowledgeBase
kb = KnowledgeBase(db_path="data/reference_knowledge.db")
kb.reindex()   # re-indexes references/; preserves learned:: — so start from a CLEAN file
```

Before committing a refreshed copy, verify it is clean:

```python
import sqlite3
n = sqlite3.connect("data/reference_knowledge.db").execute(
    "SELECT COUNT(*) FROM docs WHERE filename LIKE 'learned::%'").fetchone()[0]
assert n == 0, f"{n} engagement lessons present — DO NOT COMMIT"
```
