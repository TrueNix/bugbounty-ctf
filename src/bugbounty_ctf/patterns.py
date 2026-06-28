"""Cross-engagement PATTERN memory — generalized attack-technique sequences.

The toolkit's existing memory (``ScannerDB.findings``) is keyed by HOST: it
remembers what happened on *one* box. This module adds a second, higher tier
keyed by observable SURFACE — the shape of a target (open ports, detected
tech, generalized capabilities like ``nfs_export`` or ``imap_open``) — and
stores the GENERALIZED technique sequence that won, so a chain that worked on
one box ("nfs_enum_exports → cred_harvest_from_doc → cred_spray_mail_users →
…") can be recalled and replayed on a *different* box with the same shape.

HARD CONSTRAINT — box-specific secrets MUST NEVER enter this store.
Credentials, hostnames, flags, and URLs are box-specific noise: memorizing
them is both useless across engagements and a leak risk. This is enforced
*structurally*, not by discipline, in the same spirit as
:class:`scope.ScopeGuard` (every request funneled through one allowlist check)
and :func:`taint.render` (every target-derived string funneled through one
render valve). Here, :class:`PatternGuard` is the single fail-closed ingress:

  - Vocabularies are CLOSED allowlists. Technique/outcome/capability tokens
    that are not members are rejected (or, for capability/tech, filtered out)
    before a pattern is built — there is no free-text path into the store.
  - Every free-text field (a step's rationale) is funneled through
    :meth:`PatternGuard.redact`, which is *reject-on-uncertainty*: a detector
    that fires on a credential pair, a high-entropy run, or a flag format
    returns ``None``, and :meth:`PatternGuard.build` drops the whole pattern.
    Detectors are generic/structural — no target-specific lists.

Scattered, hand-applied redaction rots; a single chokepoint does not. Nothing
reaches persistence except through ``build``.

This module imports nothing from :mod:`engine` to keep the dependency acyclic
(engine imports patterns lazily). Phase 1 is the foundation only: the store,
the guard, ranking, and confidence math. Capture/recall wiring lands later.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------- vocabularies
# Closed set of GENERALIZED technique step tokens. "Generalized" means the
# token describes a transferable technique ("reuse harvested creds across mail
# users"), never a box-specific action ("login as kevin"). Extensible: add a
# token here plus a rationale below.
TECHNIQUE_TOKENS: frozenset[str] = frozenset(
    {
        "nfs_enum_exports",
        "nfs_uid_spoof",
        "cred_harvest_from_doc",
        "cred_spray_mail_users",
        "mailbox_secret_pivot",
        "webadmin_login_reuse",
        "admin_panel_backup_to_rce",
        "file_upload_rce",
        "sqli_dump_creds",
        "ssti_rce",
        "ssrf_metadata_creds",
        "cred_reuse_ssh",
        "su_local_cred_reuse",
        "suid_privesc",
        "sudo_privesc",
        "web_content_discovery",
        "cve_exploit",
    }
)

# Closed set of terminal/intermediate outcome tokens a chain can reach.
OUTCOME_TOKENS: frozenset[str] = frozenset(
    {"rce", "cred_pivot", "lpe", "flag", "info_leak", "foothold"}
)

# Closed set of GENERALIZED observable capabilities (the surface, not the box).
CAPABILITY_TOKENS: frozenset[str] = frozenset(
    {
        "nfs_export",
        "imap_open",
        "smtp_open",
        "webmail_vhost",
        "web_app",
        "version_banner",
        "smb_open",
    }
)

# Tech vocabulary reused from KnowledgeBase.TECH_KEYWORDS (lowercased keys), so
# the two memory tiers speak the same tech language. Imported lazily/defensively
# to avoid coupling at module import; falls back to a sensible static set.
try:  # pragma: no cover - trivial import guard
    from bugbounty_ctf.knowledge import KnowledgeBase as _KB

    TECH_TOKENS: frozenset[str] = frozenset(k.lower() for k in _KB.TECH_KEYWORDS)
except Exception:  # pragma: no cover - defensive fallback
    TECH_TOKENS = frozenset(
        {
            "nginx",
            "flask",
            "django",
            "php",
            "node.js",
            "java",
            "sqlite",
            "mysql",
            "postgresql",
            "mongodb",
            "docker",
            "jinja2",
        }
    )

# Best-effort map from a finding's ``vuln_type``/``source`` string to a
# generalized technique token. Unknown keys yield None so the caller can DROP
# the step rather than invent one.
VULN_TO_TECHNIQUE: dict[str, str | None] = {
    "sqli": "sqli_dump_creds",
    "sql_injection": "sqli_dump_creds",
    "ssti": "ssti_rce",
    "ssti_rce": "ssti_rce",
    "ssrf": "ssrf_metadata_creds",
    "ssrf_aws_metadata": "ssrf_metadata_creds",
    "ssrf_aws_credentials": "ssrf_metadata_creds",
    "file_upload": "file_upload_rce",
    "upload_rce": "file_upload_rce",
    "nfs": "nfs_enum_exports",
    "nfs_export": "nfs_enum_exports",
    "cve": "cve_exploit",
    "cve_exploit": "cve_exploit",
    "content_discovery": "web_content_discovery",
    "dir_bruteforce": "web_content_discovery",
    "suid": "suid_privesc",
    "sudo": "sudo_privesc",
    "cred_reuse": "cred_reuse_ssh",
    "ssh_cred_reuse": "cred_reuse_ssh",
}

# One GENERALIZED, secret-free sentence per technique. These ship with the
# pattern as guidance; they describe the transferable idea, not a box detail.
TECHNIQUE_RATIONALES: dict[str, str] = {
    "nfs_enum_exports": "Enumerate NFS exports — world-readable shares often leak files.",
    "nfs_uid_spoof": "Spoof a local UID to read NFS files restricted by uid — no_root_squash is common.",
    "cred_harvest_from_doc": "Harvest credentials embedded in leaked documents or config files.",
    "cred_spray_mail_users": "Reuse harvested credentials across all mail users — password reuse is common.",
    "mailbox_secret_pivot": "Read mailboxes for secrets, resets, or onward credentials to pivot.",
    "webadmin_login_reuse": "Reuse harvested credentials against admin/web login surfaces.",
    "admin_panel_backup_to_rce": "Abuse an admin panel backup/restore or upload feature to gain code execution.",
    "file_upload_rce": "Upload an executable file type to a writable web path to gain code execution.",
    "sqli_dump_creds": "Use SQL injection to dump credential tables for reuse.",
    "ssti_rce": "Escalate server-side template injection to code execution.",
    "ssrf_metadata_creds": "Use SSRF to reach the cloud metadata service and pull instance credentials.",
    "cred_reuse_ssh": "Reuse harvested credentials against SSH — operators reuse passwords.",
    "su_local_cred_reuse": "Reuse a harvested password with su to switch to another local user.",
    "suid_privesc": "Abuse a misconfigured SUID binary to escalate privileges.",
    "sudo_privesc": "Abuse a permissive sudo rule to escalate privileges.",
    "web_content_discovery": "Brute-force hidden web content to expand the attack surface.",
    "cve_exploit": "Match a version banner to a known CVE and run the public exploit.",
}

# Flag formats — mirrors engine.ResponseDiff.CONTENT_PATTERNS["flag_found"].
# Duplicated (not imported) so patterns.py stays free of an engine dependency.
_FLAG_RE = re.compile(r"flag\{|CTF\{|pwn\{|secret\{|key\{", re.IGNORECASE)

# Credential-pair near a secret keyword (e.g. ``password: hunter2longvalue``,
# ``token=abcd1234``). Generic/structural — no target-specific values.
_CRED_KEYWORD_RE = re.compile(r"(?i)(pass|pwd|secret|token|login|cred)\S{0,12}[:=]\s*\S{4,}")
# A bare ``user:secret``-style pair (6+ char secret). Rejected outright when the
# secret half is password-shaped (mixed character classes — see
# :func:`_password_shaped`), or when a cred-ish keyword sits adjacent.
_BARE_PAIR_RE = re.compile(r"(\S+):(\S{6,})")
_ADJ_KEYWORD_RE = re.compile(r"(?i)(pass|pwd|secret|token|login|cred|user|username)")

# FQDN ending in a common TLD/zone → replaced with ``<host>``. Labels allow an
# underscore so CTF-style hostnames (``support_001.enigma.htb``) are caught too.
_FQDN_RE = re.compile(
    r"\b[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.(?:htb|local|com|net|org|io|internal)\b",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE)
# A URL, or a path with more than two segments → ``<path>``.
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://\S+", re.IGNORECASE)
_PATH_RE = re.compile(r"/[^\s/]+(?:/[^\s/]+){2,}/?")

# A whitespace-delimited token of this length with entropy above the bar is
# treated as a secret and REJECTED. Conservative: reject-on-uncertainty — but
# scoped to *opaque* runs (alnum-only, mixing letters and digits) so legible
# identifiers/technique names ("admin_panel_backup_to_rce") and hostnames (which
# are stripped to <host> first) do not trip it.
_ENTROPY_MIN_LEN = 12
_ENTROPY_THRESHOLD = 3.5


def _password_shaped(value: str) -> bool:
    """True if ``value`` mixes character classes the way a password does.

    Two or more of {lowercase, uppercase, digit, symbol} present in a 6+ char
    run is a generic, target-agnostic signal that a ``user:value`` half is a
    credential rather than, say, a URL scheme split or a ratio.
    """
    if len(value) < 6:
        return False
    classes = (
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    )
    return sum(classes) >= 2


def _looks_secret(token: str) -> bool:
    """True if ``token`` looks like an opaque high-entropy secret blob.

    Requires: length >= 12, alphanumeric-only (no ``_`` / ``-`` / ``.`` word
    separators), a mix of letters and digits, and Shannon entropy above the bar.
    This distinguishes a random key/token from a long-but-legible identifier or
    a dotted hostname, keeping the detector conservative without rejecting every
    long word.
    """
    if len(token) < _ENTROPY_MIN_LEN or not token.isalnum():
        return False
    has_alpha = any(c.isalpha() for c in token)
    has_digit = any(c.isdigit() for c in token)
    if not (has_alpha and has_digit):
        return False
    return _shannon_entropy(token) > _ENTROPY_THRESHOLD


def _shannon_entropy(token: str) -> float:
    """Shannon entropy (bits/char) of ``token`` — a high-entropy proxy for secrets."""
    if not token:
        return 0.0
    counts: dict[str, int] = {}
    for ch in token:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(token)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def jaccard(a: Iterable[object], b: Iterable[object]) -> float:
    """Jaccard similarity of two iterables as sets. Empty ∩ Empty → 1.0."""
    set_a = set(a)
    set_b = set(b)
    union = set_a | set_b
    if not union:
        return 1.0
    return len(set_a & set_b) / len(union)


def beta_confidence(worked: int, failed: int) -> float:
    """Laplace/Beta-smoothed success rate: ``(worked + 1) / (worked + failed + 2)``.

    Smoothing keeps a single early win from reading as certainty and a single
    early loss from reading as worthless: (0,0)→0.5, (1,0)→0.667, (1,8)→0.2.
    """
    return (worked + 1) / (worked + failed + 2)


def compute_id(
    ports: tuple[int, ...],
    tech: tuple[str, ...],
    capabilities: tuple[str, ...],
    steps: tuple[TechniqueStep, ...],
) -> str:
    """SHA-1 of the surface + ordered technique sequence.

    Surface components (ports/tech/capabilities) are sorted so the id is
    order-insensitive there; the step sequence ORDER is preserved, so two
    chains over the same surface with a different technique order get distinct
    ids (the order is the knowledge).
    """
    parts = (
        sorted(str(p) for p in ports)
        + sorted(tech)
        + sorted(capabilities)
        + [s.technique for s in steps]
    )
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TechniqueStep:
    """One generalized step in an attack chain — never box-specific."""

    technique: str
    rationale: str
    tool_hint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "rationale": self.rationale,
            "tool_hint": self.tool_hint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TechniqueStep:
        return cls(
            technique=str(data.get("technique", "")),
            rationale=str(data.get("rationale", "")),
            tool_hint=str(data.get("tool_hint", "")),
        )


@dataclass(frozen=True)
class AttackPattern:
    """A generalized, surface-keyed attack chain — the unit of cross-box memory.

    Holds only generalized tokens and redacted rationales (see module docstring
    / :class:`PatternGuard`); it must never carry box-specific secrets.
    """

    pattern_id: str
    ports: tuple[int, ...]
    tech: tuple[str, ...]
    capabilities: tuple[str, ...]
    steps: tuple[TechniqueStep, ...]
    outcome: str
    provenance: tuple[str, ...]
    confidence: float
    applied: int
    worked: int
    failed: int
    created_at: str
    last_seen: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "ports": list(self.ports),
            "tech": list(self.tech),
            "capabilities": list(self.capabilities),
            "steps": [s.to_dict() for s in self.steps],
            "outcome": self.outcome,
            "provenance": list(self.provenance),
            "confidence": self.confidence,
            "applied": self.applied,
            "worked": self.worked,
            "failed": self.failed,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackPattern:
        steps = tuple(TechniqueStep.from_dict(s) for s in data.get("steps", []))
        return cls(
            pattern_id=str(data.get("pattern_id", "")),
            ports=tuple(int(p) for p in data.get("ports", [])),
            tech=tuple(str(t) for t in data.get("tech", [])),
            capabilities=tuple(str(c) for c in data.get("capabilities", [])),
            steps=steps,
            outcome=str(data.get("outcome", "")),
            provenance=tuple(str(p) for p in data.get("provenance", [])),
            confidence=float(data.get("confidence", 0.0)),
            applied=int(data.get("applied", 0)),
            worked=int(data.get("worked", 0)),
            failed=int(data.get("failed", 0)),
            created_at=str(data.get("created_at", "")),
            last_seen=str(data.get("last_seen", "")),
        )


class PatternGuard:
    """The single fail-closed ingress to the pattern store.

    Mirrors :class:`scope.ScopeGuard` and :func:`taint.render`: a *mechanical*
    boundary, not a discipline. Two layers enforce the no-memorize-secrets
    constraint:

      1. Allowlist — :meth:`build` validates every token against the closed
         vocabularies (rejecting invalid steps/outcome outright; filtering
         invalid tech/capabilities), so no free-text token reaches the store.
      2. Redaction — :meth:`redact` is reject-on-uncertainty: it strips
         host/ip/email/path noise but RETURNS ``None`` (rejecting the whole
         pattern) the moment a credential, high-entropy run, or flag is seen.
    """

    @staticmethod
    def redact(text: str) -> str | None:
        """Return a cleaned, secret-free string, or ``None`` to REJECT.

        Detectors are generic/structural — no target-specific lists. A ``None``
        return signals the caller to DROP the entire pattern (fail-closed), so
        this is deliberately conservative: anything that smells like a secret
        rejects rather than risking it entering cross-engagement memory.

        Reject (return None): a credential pair near a secret keyword, a
        bare ``user:secret`` adjacent to such a keyword, an opaque high-entropy
        secret run (see :func:`_looks_secret`), or a flag format.
        Strip (replace, keep going): FQDN → ``<host>``, IPv4 → ``<ip>``,
        email → ``<user>``, URL or deep path → ``<path>``.

        Structural noise (URL/email/host/ip/path) is stripped FIRST, then the
        ``user:secret`` and entropy detectors run on the cleaned remainder — so
        a URL or dotted hostname becomes a placeholder before it can be misread
        as a credential pair or a secret blob.
        """
        if _CRED_KEYWORD_RE.search(text):
            return None
        if _FLAG_RE.search(text):
            return None

        cleaned = _URL_RE.sub("<path>", text)
        cleaned = _EMAIL_RE.sub("<user>", cleaned)
        cleaned = _FQDN_RE.sub("<host>", cleaned)
        cleaned = _IPV4_RE.sub("<ip>", cleaned)
        cleaned = _PATH_RE.sub("<path>", cleaned)

        # A bare ``user:secret`` pair: reject when the secret half is
        # password-shaped (mixed character classes), or when a cred-ish keyword
        # sits adjacent in the text. Runs after stripping so a placeholdered URL
        # ("<path>") no longer reads as a pair.
        for match in _BARE_PAIR_RE.finditer(cleaned):
            if _password_shaped(match.group(2)) or _ADJ_KEYWORD_RE.search(cleaned):
                return None

        # Prose credential: a secret keyword anywhere alongside a secret-shaped
        # token (no ':'/'=' needed — e.g. "the password is Enigma2024!"). The
        # cred regexes above require a separator; this catches the narrated form.
        # Secret-shaped = 6+ chars mixing letters AND digits, so ordinary words
        # ("credentials", "Harvest") and slashed terms ("admin/web") don't trip.
        def _looks_like_password(tok: str) -> bool:
            t = tok.strip(".,;:!?\"'()[]")
            return len(t) >= 6 and any(c.isalpha() for c in t) and any(c.isdigit() for c in t)

        if _ADJ_KEYWORD_RE.search(cleaned) and any(
            _looks_like_password(tok) for tok in cleaned.split()
        ):
            return None

        # Entropy is the last line of defence: an opaque secret blob that none
        # of the structural strippers matched rejects the whole pattern.
        for token in cleaned.split():
            if _looks_secret(token):
                return None
        return cleaned

    @classmethod
    def build(
        cls,
        *,
        ports: tuple[int, ...],
        tech: tuple[str, ...],
        capabilities: tuple[str, ...],
        steps: tuple[TechniqueStep, ...],
        outcome: str,
        provenance: tuple[str, ...],
        now: str,
    ) -> AttackPattern | None:
        """Construct a validated :class:`AttackPattern`, or ``None`` (fail-closed).

        ``now`` is an ISO timestamp passed IN (never read from the clock here)
        so this stays deterministic for tests. Returns ``None`` if any step
        technique is not a known token, the outcome is unknown, a port is not
        an int, or any rationale fails :meth:`redact`. Invalid tech and
        capabilities are FILTERED via the allowlist before validation (a
        surface observation can be partly noise); invalid steps/outcome are
        fatal (the technique sequence is the knowledge — it must be exact).
        """
        if outcome not in OUTCOME_TOKENS:
            return None
        if not all(isinstance(p, int) for p in ports):
            return None

        # Allowlist-filter the (noisy) surface dimensions before validating.
        clean_tech = tuple(t for t in tech if t.lower() in TECH_TOKENS)
        clean_caps = tuple(c for c in capabilities if c in CAPABILITY_TOKENS)

        clean_steps: list[TechniqueStep] = []
        for step in steps:
            if step.technique not in TECHNIQUE_TOKENS:
                return None
            redacted = cls.redact(step.rationale)
            if redacted is None:
                return None
            clean_steps.append(
                TechniqueStep(
                    technique=step.technique,
                    rationale=redacted,
                    tool_hint=step.tool_hint,
                )
            )

        steps_tuple = tuple(clean_steps)
        pattern_id = compute_id(ports, clean_tech, clean_caps, steps_tuple)
        return AttackPattern(
            pattern_id=pattern_id,
            ports=ports,
            tech=clean_tech,
            capabilities=clean_caps,
            steps=steps_tuple,
            outcome=outcome,
            provenance=provenance,
            confidence=beta_confidence(0, 0),
            applied=0,
            worked=0,
            failed=0,
            created_at=now,
            last_seen=now,
        )


def rank_patterns(
    candidates: list[AttackPattern],
    *,
    ports: tuple[int, ...],
    tech: tuple[str, ...],
    capabilities: tuple[str, ...],
    w_tech: float = 0.4,
    w_cap: float = 0.4,
    w_port: float = 0.1,
    w_conf: float = 0.1,
) -> list[AttackPattern]:
    """Rank candidates by surface overlap with the current target, descending.

    Score = ``w_tech*jaccard(tech) + w_cap*jaccard(caps) + w_port*jaccard(ports)
    + w_conf*confidence``. A pattern that shares tech AND capabilities with the
    target outranks one that shares neither — that is the whole point of a
    surface-keyed memory: recall what fits this shape.
    """

    def score(p: AttackPattern) -> float:
        return (
            w_tech * jaccard(p.tech, tech)
            + w_cap * jaccard(p.capabilities, capabilities)
            + w_port * jaccard(p.ports, ports)
            + w_conf * p.confidence
        )

    return sorted(candidates, key=score, reverse=True)
