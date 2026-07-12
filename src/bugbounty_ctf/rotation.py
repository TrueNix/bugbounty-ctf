"""Bound the growth of append-only stores under ``~/.hermes``.

Two primitives, both safe for concurrent writers:

- :func:`rotate_jsonl` — size-based rotation for append-only JSONL logs
  (``file`` -> ``file.1`` -> ``file.2`` …, dropping the oldest beyond ``keep``).
- :func:`prune_files` — retention for directories that accumulate one file per
  run (e.g. saved reports): keep the newest ``keep``, delete the rest.

Rotation runs under an exclusive lock so a second writer observes the rotated
file and becomes a no-op rather than racing.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
from pathlib import Path

DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_KEEP = 3


def rotate_jsonl(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    keep: int = DEFAULT_KEEP,
) -> bool:
    """Rotate ``path`` if it is at least ``max_bytes``. Returns True if rotated.

    ``path`` becomes ``path.1``; existing ``path.N`` shift up by one and the
    oldest beyond ``keep`` is dropped. Safe to call before every append: it
    stats first (cheap) and only takes the lock when rotation is actually due.
    """
    target = Path(path)
    if not _oversized(target, max_bytes):
        return False
    fd = os.open(str(target), os.O_RDONLY | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        if not _oversized(target, max_bytes):
            return False  # another writer rotated while we waited for the lock
        _shift(target, keep)
        return True
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def prune_files(directory: str | Path, pattern: str = "*", *, keep: int = 50) -> list[Path]:
    """Keep the newest ``keep`` files matching ``pattern``; delete the rest.

    Bounds directories that gain one file per run (saved reports, cache dumps).
    Returns the deleted paths. A no-op when the directory holds ``keep`` or fewer.
    """
    base = Path(directory)
    if keep < 0 or not base.is_dir():
        return []
    files = sorted(
        (entry for entry in base.glob(pattern) if entry.is_file()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    removed: list[Path] = []
    for stale in files[keep:]:
        with contextlib.suppress(OSError):
            stale.unlink()
            removed.append(stale)
    return removed


def _oversized(path: Path, max_bytes: int) -> bool:
    try:
        return path.stat().st_size >= max_bytes
    except FileNotFoundError:
        return False


def _shift(path: Path, keep: int) -> None:
    oldest = path.with_suffix(path.suffix + f".{keep}")
    if oldest.exists():
        oldest.unlink()
    for index in range(keep - 1, 0, -1):
        src = path.with_suffix(path.suffix + f".{index}")
        dst = path.with_suffix(path.suffix + f".{index + 1}")
        if src.exists():
            os.replace(str(src), str(dst))
    os.replace(str(path), str(path.with_suffix(path.suffix + ".1")))
