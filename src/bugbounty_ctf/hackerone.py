"""HackerOne scope ingestion — turn a program's structured scopes into a guard.

Bug-bounty programs define exactly which assets are in scope. Rather than
hand-typing an allowlist, this client pulls a program's structured scopes from
the HackerOne API and builds a :class:`~bugbounty_ctf.scope.ScopeGuard` from the
host assets that are eligible for submission. Point a scanner at that guard (plus
an :class:`~bugbounty_ctf.audit_log.AuditLog`) and every request is checked, and
recorded, against the program's authoritative scope:

    from bugbounty_ctf import SecurityScanner
    from bugbounty_ctf.audit_log import AuditLog
    from bugbounty_ctf.hackerone import HackerOneClient

    guard = HackerOneClient().scope_guard("example-program")
    scanner = SecurityScanner("https://app.example.com/", scope=guard, audit_log=AuditLog())

Credentials come from ``H1_USERNAME`` / ``H1_API_TOKEN`` (create a token at
https://hackerone.com/settings/api_token/edit) or the constructor. The HTTP layer
is injectable so tests can run against a mocked API with no network.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

import requests

from bugbounty_ctf.scope import ScopeGuard

DEFAULT_BASE_URL = "https://api.hackerone.com"
DEFAULT_TIMEOUT = 15.0
_MAX_PAGES = 50
# Asset types that map to a host allowlist. Mobile apps, CIDRs, source repos,
# etc. are real scope but not host-based web targets, so they are not added to a
# ScopeGuard (which is a host allowlist).
_HOST_ASSET_TYPES = frozenset({"URL", "WILDCARD", "DOMAIN"})


class HackerOneError(RuntimeError):
    """A HackerOne API failure (missing credentials, auth, network, or bad response)."""


class _Response(Protocol):
    status_code: int

    def json(self) -> Any: ...


class _Session(Protocol):
    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        auth: tuple[str, str],
        timeout: float,
    ) -> _Response: ...


@dataclass(frozen=True, slots=True)
class Scope:
    """One structured-scope asset from a program's policy."""

    asset_type: str
    asset_identifier: str
    eligible_for_submission: bool
    eligible_for_bounty: bool
    instruction: str = ""

    @property
    def is_host_asset(self) -> bool:
        return self.asset_type in _HOST_ASSET_TYPES


class HackerOneClient:
    """Read a HackerOne program's scope and build a guard from it."""

    def __init__(
        self,
        username: str | None = None,
        api_token: str | None = None,
        *,
        base_url: str = DEFAULT_BASE_URL,
        session: _Session | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.username = username or os.environ.get("H1_USERNAME") or ""
        self.api_token = api_token or os.environ.get("H1_API_TOKEN") or ""
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session = session

    def structured_scopes(self, handle: str) -> list[Scope]:
        """Return every structured scope for ``handle`` (following pagination)."""
        if not handle.strip() or handle != handle.strip() or "/" in handle:
            raise HackerOneError(f"invalid program handle: {handle!r}")
        if not self.username or not self.api_token:
            raise HackerOneError(
                "HackerOne credentials missing; set H1_USERNAME and H1_API_TOKEN "
                "(https://hackerone.com/settings/api_token/edit)."
            )
        session = self._require_session()
        url = f"{self.base_url}/v1/hackers/programs/{handle}/structured_scopes"
        scopes: list[Scope] = []
        for _ in range(_MAX_PAGES):
            if not url:
                break
            body = self._get_json(session, url, handle)
            data = body.get("data")
            if isinstance(data, list):
                for item in data:
                    scope = _scope_from_item(item)
                    if scope is not None:
                        scopes.append(scope)
            url = _next_link(body)
        return scopes

    def scope_guard(
        self,
        handle: str,
        *,
        bounty_only: bool = False,
        allow_subdomains: bool = True,
    ) -> ScopeGuard:
        """Build a :class:`ScopeGuard` from a program's in-scope host assets.

        Only assets eligible for submission are added (plus eligible for bounty
        when ``bounty_only`` is set). Non-host assets (mobile apps, CIDRs, …) are
        skipped because a guard is a host allowlist.
        """
        guard = ScopeGuard(allow_subdomains=allow_subdomains)
        for scope in self.structured_scopes(handle):
            if not scope.eligible_for_submission:
                continue
            if bounty_only and not scope.eligible_for_bounty:
                continue
            if scope.is_host_asset and scope.asset_identifier.strip():
                guard.add(scope.asset_identifier)
        return guard

    def _require_session(self) -> _Session:
        if self._session is None:
            self._session = cast("_Session", requests.Session())
        return self._session

    def _get_json(self, session: _Session, url: str, handle: str) -> Mapping[str, Any]:
        try:
            response = session.get(
                url,
                headers={"Accept": "application/json"},
                auth=(self.username, self.api_token),
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise HackerOneError(f"HackerOne request failed: {exc}") from exc
        status = response.status_code
        if status in (401, 403):
            raise HackerOneError(
                f"HackerOne auth rejected (HTTP {status}); check H1_USERNAME/H1_API_TOKEN."
            )
        if status == 404:
            raise HackerOneError(f"HackerOne program not found: {handle!r}")
        if status != 200:
            raise HackerOneError(f"HackerOne API returned HTTP {status}")
        try:
            body = response.json()
        except ValueError as exc:
            raise HackerOneError("HackerOne API returned invalid JSON") from exc
        if not isinstance(body, Mapping):
            raise HackerOneError("HackerOne API returned an unexpected payload")
        return cast("Mapping[str, Any]", body)


def _next_link(body: Mapping[str, Any]) -> str:
    links = body.get("links")
    if isinstance(links, Mapping):
        nxt = links.get("next")
        if isinstance(nxt, str):
            return nxt
    return ""


def _scope_from_item(item: Any) -> Scope | None:
    if not isinstance(item, Mapping):
        return None
    attributes = item.get("attributes")
    if not isinstance(attributes, Mapping):
        return None
    asset_type = attributes.get("asset_type")
    asset_identifier = attributes.get("asset_identifier")
    if not isinstance(asset_type, str) or not isinstance(asset_identifier, str):
        return None
    instruction = attributes.get("instruction")
    return Scope(
        asset_type=asset_type,
        asset_identifier=asset_identifier,
        eligible_for_submission=bool(attributes.get("eligible_for_submission", True)),
        eligible_for_bounty=bool(attributes.get("eligible_for_bounty", False)),
        instruction=instruction if isinstance(instruction, str) else "",
    )
