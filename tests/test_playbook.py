"""Tests for the declarative triage playbook.

The drift guard is the point of this file: it fails if a shipped capability
module has no track, or if a track points at a dead import path.
"""

from __future__ import annotations

from bugbounty_ctf import patterns
from bugbounty_ctf.playbook import Track, load_tracks, resolve_entrypoint, select

# Every shipped infra/capability entrypoint the manifest MUST surface a track for.
# Adding a capability module to the toolkit without adding it here (and to
# playbook.json) is exactly the failure this guard prevents.
KNOWN_CAPABILITY_ENTRYPOINTS = {
    "bugbounty_ctf.api:NFSEnumerator",
    "bugbounty_ctf.api:MailEnumerator",
    "bugbounty_ctf.api:correlate_cves",
    "bugbounty_ctf.api:SecurityScanner",
}


def _ids(tracks: list[Track]) -> set[str]:
    return {t.id for t in tracks}


def test_load_tracks_returns_expected_ids() -> None:
    assert _ids(load_tracks()) == {"web", "nfs", "mail", "cve"}


def test_select_nfs_port_includes_always_cve() -> None:
    assert _ids(select(ports=[2049])) == {"nfs", "cve"}


def test_select_mail_port_includes_always_cve() -> None:
    assert _ids(select(ports=[993])) == {"mail", "cve"}


def test_select_web_port_includes_always_cve() -> None:
    assert _ids(select(ports=[80])) == {"web", "cve"}


def test_select_by_tech_matches_case_insensitively() -> None:
    assert _ids(select(tech=["nginx"])) == {"web", "cve"}
    assert _ids(select(tech=["NGINX"])) == {"web", "cve"}


def test_select_with_no_surface_returns_only_always_tracks() -> None:
    assert _ids(select()) == {"cve"}


def test_select_preserves_manifest_order_and_dedups() -> None:
    # A port and tech that both hit web must yield web once, in manifest order.
    selected = select(ports=[80], tech=["nginx"])
    assert [t.id for t in selected] == ["web", "cve"]


def test_drift_guard_every_known_capability_has_a_track() -> None:
    manifest_entrypoints = {t.entrypoint for t in load_tracks()}
    missing = KNOWN_CAPABILITY_ENTRYPOINTS - manifest_entrypoints
    assert not missing, f"shipped capabilities with no track: {missing}"


def test_drift_guard_every_track_entrypoint_imports() -> None:
    for track in load_tracks():
        resolved = resolve_entrypoint(track)
        assert resolved is not None, f"dead entrypoint: {track.entrypoint}"


def test_drift_guard_every_track_capability_is_a_known_token() -> None:
    for track in load_tracks():
        assert track.capability in patterns.CAPABILITY_TOKENS, (
            f"track {track.id!r} has capability {track.capability!r} "
            "not in patterns.CAPABILITY_TOKENS"
        )
