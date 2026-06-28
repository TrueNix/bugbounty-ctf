"""Trust-boundary valve for target-derived text entering sub-agent prompts.

Target-controlled data — HTTP response bodies, banners, reflected parameters,
form field names — flows from the target into ScannerDB / findings and then
gets interpolated into ``hermes -z --yolo`` sub-agent prompts. Unescaped, a
newline in a banner can forge a new prompt line (``\\n## System:`` …) or a
fake ``</FINDINGS>`` tag can derail the structured-output contract. This is a
prompt-injection vector with the same shape as a classic CRLF/log-injection.

The fix is structural, not disciplinary. Just as :class:`scope.ScopeGuard`
makes scope a *mechanical* boundary — every request is funneled through one
allowlist check rather than relying on each call site to "remember" to stay in
scope — this module funnels every target-derived string through one render
valve before it can become prompt structure. Scattered, hand-applied
sanitization rots; a single chokepoint does not.

Two entry points:
  - :func:`render` for a scalar value interpolated into a prompt line.
  - :func:`render_json` for a (possibly nested) structure dumped as a JSON
    blob, so target data buried inside a dict/list is cleaned leaf-by-leaf
    before serialization.

:class:`Tainted` is a thin ``str`` marker for target-derived text. Phase 0
does not yet type-enforce its use (the findings model stays a plain ``dict``);
it documents intent and is available for a later persistence phase that wires
``Tainted``-typed fields end to end.
"""

from __future__ import annotations

import json
from typing import Any

# C0 control chars (U+0000 to U+001F) plus DEL (U+007F). Tab (U+0009) is handled
# specially — collapsed to a space rather than dropped — so it cannot be used
# to smuggle layout, while normal spaces survive.
_CONTROL_CHARS = frozenset(chr(c) for c in range(0x20)) | {"\x7f"}

# Default per-leaf cap inside render_json: generous enough not to mangle real
# payloads/evidence, tight enough that one leaf cannot blow the whole blob.
_JSON_LEAF_MAXLEN = 500


class Tainted(str):
    """Target-derived text; must be ``render()``ed before entering a prompt."""

    __slots__ = ()


def render(value: object, *, maxlen: int = 120) -> str:
    """Flatten one target-derived value so it cannot inject prompt structure.

    Coerces ``value`` to ``str``, strips all C0 control characters (``\\r``,
    ``\\n``, ``\\x00``, …) and DEL, collapses tabs to a single space, then
    truncates to ``maxlen``. Normal spaces are preserved. The result is safe to
    drop into a single prompt line: it can contain no newline that would start a
    new line, and no NUL.
    """
    text = str(value)
    cleaned = "".join(" " if ch == "\t" else "" if ch in _CONTROL_CHARS else ch for ch in text)
    return cleaned[:maxlen]


def _clean_leaves(obj: object, *, leaf_maxlen: int) -> Any:
    """Recursively rebuild ``obj``, ``render()``-ing every ``str`` leaf.

    Returns a new structure (no mutation of the input). Non-container,
    non-``str`` leaves (int, float, bool, None) pass through unchanged;
    anything else is left for ``json.dumps(default=str)`` to coerce.
    """
    if isinstance(obj, str):
        return render(obj, maxlen=leaf_maxlen)
    if isinstance(obj, dict):
        return {
            render(str(k), maxlen=leaf_maxlen): _clean_leaves(v, leaf_maxlen=leaf_maxlen)
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_clean_leaves(item, leaf_maxlen=leaf_maxlen) for item in obj]
    return obj


def render_json(obj: object, *, maxlen: int = 2000) -> str:
    """Serialize ``obj`` to JSON after rendering every string leaf.

    Deep-copies ``obj`` (dicts/lists/tuples), applying :func:`render` to every
    string key and value so newlines, NULs, and forged tags buried inside the
    structure become inert text. The cleaned structure is then ``json.dumps``-ed
    (with ``default=str`` for stray objects) and the whole blob capped at
    ``maxlen``. Because each leaf is escaped before serialization, the output
    contains no bare newline that could forge a prompt line.
    """
    cleaned = _clean_leaves(obj, leaf_maxlen=_JSON_LEAF_MAXLEN)
    dumped = json.dumps(cleaned, indent=2, default=str)
    return dumped[:maxlen]
