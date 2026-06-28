"""Executable form of the SKILL.md "Triage the Surface" table.

The triage step in ``SKILL.md`` maps what a target exposes (open ports, detected
technologies) to which toolkit track to run. Historically that mapping lived only
as prose in an 877-line skill document, so shipped capability modules (for
example ``nfs_enum`` and ``mail_enum``) could be invisible to the agent: a module
shipped but no prose line pointed at it, and nothing failed.

This module turns that mapping into a declarative, code-readable manifest
(``data/playbook.json``) plus a selector. :func:`load_tracks` parses the
manifest, :func:`select` returns the tracks that apply to a given surface, and
:func:`resolve_entrypoint` imports a track's entrypoint. A drift test
(``tests/test_playbook.py``) walks every track to assert each entrypoint imports
and that every shipped capability is reachable, so a new module cannot ship
without a corresponding track and a track cannot point at a dead path.
"""

from __future__ import annotations

import importlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files

__all__ = ["Track", "load_tracks", "resolve_entrypoint", "select"]


@dataclass(frozen=True)
class Track:
    """A single triage track: a trigger condition mapped to a toolkit entrypoint.

    Tuples (not lists) are used for ``ports`` and ``tech`` so instances stay
    hashable and immutable.
    """

    id: str
    name: str
    ports: tuple[int, ...]
    tech: tuple[str, ...]
    entrypoint: str
    parallel_safe: bool
    reference: str
    instruction: str
    always: bool = False


@lru_cache(maxsize=1)
def load_tracks() -> list[Track]:
    """Load and parse ``data/playbook.json`` into :class:`Track` objects.

    Uses :func:`importlib.resources.files` so it resolves for both installed and
    editable installs. Result is cached for the process lifetime.
    """
    manifest = files("bugbounty_ctf").joinpath("data/playbook.json").read_text(encoding="utf-8")
    raw: list[dict[str, object]] = json.loads(manifest)
    tracks: list[Track] = []
    for entry in raw:
        trigger = entry["trigger"]
        assert isinstance(trigger, dict)
        ports = trigger.get("ports", [])
        tech = trigger.get("tech", [])
        assert isinstance(ports, list)
        assert isinstance(tech, list)
        tracks.append(
            Track(
                id=str(entry["id"]),
                name=str(entry["name"]),
                ports=tuple(int(p) for p in ports),
                tech=tuple(str(t) for t in tech),
                entrypoint=str(entry["entrypoint"]),
                parallel_safe=bool(entry["parallel_safe"]),
                reference=str(entry["reference"]),
                instruction=str(entry["instruction"]),
                always=bool(entry.get("always", False)),
            )
        )
    return tracks


def select(
    ports: Iterable[int] | None = None,
    tech: Iterable[str] | None = None,
) -> list[Track]:
    """Return the tracks that apply to the given surface.

    A track is selected when its trigger ports intersect ``ports`` OR its trigger
    tech case-insensitively matches any of ``tech``. Tracks marked ``always`` are
    always included. Results preserve manifest order and are de-duplicated.
    """
    port_set = set(ports) if ports is not None else set()
    tech_set = {t.lower() for t in tech} if tech is not None else set()

    selected: list[Track] = []
    for track in load_tracks():
        port_match = bool(set(track.ports) & port_set)
        tech_match = any(t.lower() in tech_set for t in track.tech)
        if track.always or port_match or tech_match:
            selected.append(track)
    return selected


def resolve_entrypoint(track: Track) -> object:
    """Import and return the object named by ``track.entrypoint`` ("module:attr")."""
    module_name, _, attr = track.entrypoint.partition(":")
    module = importlib.import_module(module_name)
    return getattr(module, attr)
