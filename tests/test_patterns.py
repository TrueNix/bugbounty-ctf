"""Tests for the cross-engagement PATTERN memory tier (Phase 1).

Covers the structural no-memorize-secrets boundary (PatternGuard), the
generalized-chain model (AttackPattern / TechniqueStep / compute_id), surface
ranking, Beta-smoothed confidence, and the ScannerDB pattern store.
"""

from __future__ import annotations

from bugbounty_ctf.engine import ScannerDB
from bugbounty_ctf.patterns import (
    AttackPattern,
    PatternGuard,
    TechniqueStep,
    beta_confidence,
    compute_id,
    jaccard,
    rank_patterns,
)

# A clean Enigma-like chain reused across tests.
_ENIGMA_TECHNIQUES = (
    "nfs_enum_exports",
    "cred_harvest_from_doc",
    "cred_spray_mail_users",
    "mailbox_secret_pivot",
    "webadmin_login_reuse",
    "admin_panel_backup_to_rce",
)


def _clean_steps() -> tuple[TechniqueStep, ...]:
    return tuple(
        TechniqueStep(
            technique=t,
            rationale="Reuse harvested credentials across all mail users.",
            tool_hint="manual",
        )
        for t in _ENIGMA_TECHNIQUES
    )


# --------------------------------------------------------------- redact: reject
def test_redact_rejects_credential_pair() -> None:
    assert PatternGuard.redact("kevin:Enigma2024!") is None


def test_redact_rejects_password_keyword() -> None:
    assert PatternGuard.redact("password: hunter2longvalue") is None


def test_redact_rejects_prose_credential() -> None:
    # Narrated secret with no ':'/'=' separator — the cred regexes miss it, the
    # keyword-proximity rule must catch it. Ordinary capitalized/slashed words
    # (no digits) must NOT trip it.
    assert PatternGuard.redact("the password is Enigma2024!") is None
    assert PatternGuard.redact("Harvest credentials from admin/web config") is not None


def test_redact_rejects_flag_format() -> None:
    assert PatternGuard.redact("flag{abc}") is None


def test_redact_rejects_high_entropy_token() -> None:
    # 16-char mixed token, entropy well above 3.5 bits/char.
    assert PatternGuard.redact("aZ9k2Qr7Xb3Mw1Pd") is None


# ---------------------------------------------------------------- redact: strip
def test_redact_strips_fqdn() -> None:
    cleaned = PatternGuard.redact("found on support_001.enigma.htb today")
    assert cleaned is not None
    assert "<host>" in cleaned
    assert "enigma.htb" not in cleaned


def test_redact_strips_email() -> None:
    cleaned = PatternGuard.redact("contact admin@enigma.htb for access")
    assert cleaned is not None
    assert "<user>" in cleaned


def test_redact_strips_ipv4() -> None:
    cleaned = PatternGuard.redact("hit 169.254.169.254 metadata")
    assert cleaned is not None
    assert "<ip>" in cleaned
    assert "169.254.169.254" not in cleaned


# ---------------------------------------------------------------- guard.build
def test_build_rejects_unknown_technique() -> None:
    steps = (TechniqueStep("definitely_not_a_token", "clean rationale", ""),)
    result = PatternGuard.build(
        ports=(2049,),
        tech=("flask",),
        capabilities=("nfs_export",),
        steps=steps,
        outcome="rce",
        provenance=("test",),
        now="2026-01-01T00:00:00",
    )
    assert result is None


def test_build_rejects_bad_outcome() -> None:
    result = PatternGuard.build(
        ports=(2049,),
        tech=("flask",),
        capabilities=("nfs_export",),
        steps=_clean_steps(),
        outcome="not_an_outcome",
        provenance=("test",),
        now="2026-01-01T00:00:00",
    )
    assert result is None


def test_build_rejects_step_rationale_with_credential() -> None:
    steps = (TechniqueStep("nfs_enum_exports", "creds are kevin:Enigma2024!", ""),)
    result = PatternGuard.build(
        ports=(2049,),
        tech=("flask",),
        capabilities=("nfs_export",),
        steps=steps,
        outcome="rce",
        provenance=("test",),
        now="2026-01-01T00:00:00",
    )
    assert result is None


def test_build_returns_clean_pattern() -> None:
    pattern = PatternGuard.build(
        ports=(80, 143, 2049),
        tech=("flask",),
        capabilities=("nfs_export", "imap_open", "web_app"),
        steps=_clean_steps(),
        outcome="rce",
        provenance=("enigma",),
        now="2026-01-01T00:00:00",
    )
    assert pattern is not None
    assert pattern.outcome == "rce"
    assert len(pattern.steps) == 6
    # No secret-shaped content anywhere in the built pattern. (pattern_id is a
    # deterministic SHA-1 of the surface, not box data, so it is excluded.)
    blob = " ".join(
        [
            pattern.outcome,
            *pattern.tech,
            *pattern.capabilities,
            *(s.rationale for s in pattern.steps),
            *(s.technique for s in pattern.steps),
        ]
    )
    assert PatternGuard.redact(blob) is not None
    assert "Enigma2024" not in blob
    assert "kevin" not in blob


def test_build_filters_invalid_tech_and_caps() -> None:
    pattern = PatternGuard.build(
        ports=(2049,),
        tech=("flask", "not_a_real_tech"),
        capabilities=("nfs_export", "bogus_capability"),
        steps=_clean_steps(),
        outcome="rce",
        provenance=("test",),
        now="2026-01-01T00:00:00",
    )
    assert pattern is not None
    assert pattern.tech == ("flask",)
    assert pattern.capabilities == ("nfs_export",)


# ---------------------------------------------------------------- compute_id
def test_compute_id_stable_for_same_inputs() -> None:
    steps = _clean_steps()
    id_a = compute_id((80, 2049), ("flask",), ("nfs_export",), steps)
    id_b = compute_id((2049, 80), ("flask",), ("nfs_export",), steps)
    assert id_a == id_b  # surface order does not matter


def test_compute_id_changes_with_sequence_order() -> None:
    steps = _clean_steps()
    reordered = (steps[1], steps[0], *steps[2:])
    base = compute_id((2049,), ("flask",), ("nfs_export",), steps)
    swapped = compute_id((2049,), ("flask",), ("nfs_export",), reordered)
    assert base != swapped  # step sequence ORDER is the knowledge


# ---------------------------------------------------------------- confidence
def test_beta_confidence_values() -> None:
    # Beta/Laplace smoothing: (worked + 1) / (worked + failed + 2).
    assert beta_confidence(0, 0) == 0.5
    assert round(beta_confidence(1, 0), 3) == 0.667
    # (1 + 1) / (1 + 8 + 2) == 2/11; well below the 0.15 prune floor at scale.
    assert round(beta_confidence(1, 8), 3) == 0.182


def test_jaccard_basics() -> None:
    assert jaccard(("a", "b"), ("a", "b")) == 1.0
    assert jaccard(("a",), ("b",)) == 0.0
    assert jaccard((), ()) == 1.0


# ---------------------------------------------------------------- ScannerDB
def _build_pattern(now: str = "2026-01-01T00:00:00") -> AttackPattern:
    pattern = PatternGuard.build(
        ports=(80, 143, 2049),
        tech=("flask",),
        capabilities=("nfs_export", "imap_open"),
        steps=_clean_steps(),
        outcome="rce",
        provenance=("enigma",),
        now=now,
    )
    assert pattern is not None
    return pattern


def test_save_pattern_insert_then_merge() -> None:
    db = ScannerDB(":memory:")
    base = _build_pattern()

    # First save: one win.
    first = AttackPattern(
        pattern_id=base.pattern_id,
        ports=base.ports,
        tech=base.tech,
        capabilities=base.capabilities,
        steps=base.steps,
        outcome=base.outcome,
        provenance=("enigma",),
        confidence=beta_confidence(1, 0),
        applied=1,
        worked=1,
        failed=0,
        created_at=base.created_at,
        last_seen="2026-01-01T00:00:00",
    )
    db.save_pattern(first)

    matched = db.match_patterns(base.ports, base.tech, base.capabilities)
    assert len(matched) == 1
    assert matched[0].applied == 1
    assert matched[0].worked == 1

    # Second save (same id, e.g. a different box): counts accumulate.
    second = AttackPattern(
        pattern_id=base.pattern_id,
        ports=base.ports,
        tech=base.tech,
        capabilities=base.capabilities,
        steps=base.steps,
        outcome=base.outcome,
        provenance=("orion",),
        confidence=beta_confidence(1, 0),
        applied=2,
        worked=2,
        failed=0,
        created_at=base.created_at,
        last_seen="2026-02-02T00:00:00",
    )
    db.save_pattern(second)

    merged = db.match_patterns(base.ports, base.tech, base.capabilities)
    assert len(merged) == 1
    m = merged[0]
    assert m.applied == 3
    assert m.worked == 3
    assert m.failed == 0
    assert m.confidence == beta_confidence(3, 0)
    assert set(m.provenance) == {"enigma", "orion"}
    assert m.last_seen == "2026-02-02T00:00:00"
    db.close()


def test_match_patterns_and_rank_by_surface_overlap() -> None:
    db = ScannerDB(":memory:")

    matching = _build_pattern()
    db.save_pattern(matching)

    # A pattern over a totally different surface (no tech/cap overlap).
    other = PatternGuard.build(
        ports=(22,),
        tech=("php",),
        capabilities=("smb_open",),
        steps=(TechniqueStep("suid_privesc", "Abuse a SUID binary.", ""),),
        outcome="lpe",
        provenance=("other",),
        now="2026-01-01T00:00:00",
    )
    assert other is not None
    db.save_pattern(other)

    candidates = db.match_patterns((80, 143, 2049), ("flask",), ("nfs_export", "imap_open"))
    assert len(candidates) == 2

    ranked = rank_patterns(
        candidates,
        ports=(80, 143, 2049),
        tech=("flask",),
        capabilities=("nfs_export", "imap_open"),
    )
    # The surface-matching pattern ranks first.
    assert ranked[0].pattern_id == matching.pattern_id
    assert ranked[-1].pattern_id == other.pattern_id
    db.close()


def test_prune_patterns_removes_proven_bad_keeps_good() -> None:
    db = ScannerDB(":memory:")

    # Proven-bad: applied 10 times, mostly failing → low confidence.
    bad = PatternGuard.build(
        ports=(22,),
        tech=("php",),
        capabilities=("smb_open",),
        steps=(TechniqueStep("sudo_privesc", "Abuse a sudo rule.", ""),),
        outcome="lpe",
        provenance=("bad",),
        now="2026-01-01T00:00:00",
    )
    assert bad is not None
    bad = AttackPattern(
        pattern_id=bad.pattern_id,
        ports=bad.ports,
        tech=bad.tech,
        capabilities=bad.capabilities,
        steps=bad.steps,
        outcome=bad.outcome,
        provenance=bad.provenance,
        confidence=beta_confidence(0, 9),
        applied=9,
        worked=0,
        failed=9,
        created_at=bad.created_at,
        last_seen=bad.last_seen,
    )
    db.save_pattern(bad)

    good = _build_pattern()
    db.save_pattern(good)

    deleted = db.prune_patterns(min_confidence=0.15, min_applied=5)
    assert deleted == 1

    remaining = db.match_patterns(good.ports, good.tech, good.capabilities)
    ids = {p.pattern_id for p in remaining}
    assert good.pattern_id in ids
    assert bad.pattern_id not in ids
    db.close()
