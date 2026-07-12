"""HackerOne scope ingestion tests — mocked API via an injected session."""

from __future__ import annotations

from typing import Any

import pytest

from bugbounty_ctf.hackerone import HackerOneClient, HackerOneError
from bugbounty_ctf.scope import OutOfScopeError

BASE = "https://api.hackerone.com/v1/hackers/programs/acme/structured_scopes"


class _FakeResponse:
    def __init__(self, status_code: int, payload: Any) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> Any:
        return self._payload


class _FakeSession:
    """Serves canned responses keyed by URL and records the auth it received."""

    def __init__(self, pages: dict[str, _FakeResponse]) -> None:
        self._pages = pages
        self.calls: list[tuple[str, tuple[str, str]]] = []

    def get(
        self, url: str, *, headers: Any, auth: tuple[str, str], timeout: float
    ) -> _FakeResponse:
        self.calls.append((url, auth))
        return self._pages[url]


def _scope(
    asset_type: str, identifier: str, *, submission: bool = True, bounty: bool = False
) -> dict[str, Any]:
    return {
        "attributes": {
            "asset_type": asset_type,
            "asset_identifier": identifier,
            "eligible_for_submission": submission,
            "eligible_for_bounty": bounty,
        }
    }


def _client(pages: dict[str, _FakeResponse]) -> tuple[HackerOneClient, _FakeSession]:
    session = _FakeSession(pages)
    return HackerOneClient("hunter", "tok", session=session), session


def test_structured_scopes_parses_and_sends_auth() -> None:
    client, session = _client(
        {BASE: _FakeResponse(200, {"data": [_scope("URL", "https://api.acme.com")]})}
    )

    scopes = client.structured_scopes("acme")

    assert [s.asset_identifier for s in scopes] == ["https://api.acme.com"]
    assert session.calls[0][1] == ("hunter", "tok")


def test_scope_guard_allows_in_scope_and_denies_out() -> None:
    client, _ = _client(
        {
            BASE: _FakeResponse(
                200,
                {
                    "data": [
                        _scope("WILDCARD", "*.acme.com"),
                        _scope("URL", "https://shop.acme.io"),
                        _scope("DOMAIN", "not-eligible.com", submission=False),
                        _scope("GOOGLE_PLAY_APP_ID", "com.acme.app"),
                    ]
                },
            )
        }
    )

    guard = client.scope_guard("acme")

    assert guard.is_allowed("https://api.acme.com/x") is True  # wildcard subdomain
    assert guard.is_allowed("https://shop.acme.io/") is True  # url host
    assert guard.is_allowed("https://evil.test/") is False  # out of scope
    assert guard.is_allowed("https://not-eligible.com/") is False  # submission=False filtered
    with pytest.raises(OutOfScopeError):
        guard.check("https://evil.test/x")


def test_scope_guard_bounty_only_filters_vdp_assets() -> None:
    client, _ = _client(
        {
            BASE: _FakeResponse(
                200,
                {
                    "data": [
                        _scope("DOMAIN", "paid.acme.com", bounty=True),
                        _scope("DOMAIN", "vdp.acme.com", bounty=False),
                    ]
                },
            )
        }
    )

    guard = client.scope_guard("acme", bounty_only=True)

    assert guard.is_allowed("https://paid.acme.com/") is True
    assert guard.is_allowed("https://vdp.acme.com/") is False


def test_pagination_follows_next_link() -> None:
    page2 = f"{BASE}?page[number]=2"
    client, _ = _client(
        {
            BASE: _FakeResponse(
                200, {"data": [_scope("DOMAIN", "a.acme.com")], "links": {"next": page2}}
            ),
            page2: _FakeResponse(200, {"data": [_scope("DOMAIN", "b.acme.com")], "links": {}}),
        }
    )

    scopes = client.structured_scopes("acme")

    assert {s.asset_identifier for s in scopes} == {"a.acme.com", "b.acme.com"}


def test_missing_credentials_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("H1_USERNAME", raising=False)
    monkeypatch.delenv("H1_API_TOKEN", raising=False)
    client = HackerOneClient("", "", session=_FakeSession({}))

    with pytest.raises(HackerOneError):
        client.structured_scopes("acme")


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_http_errors_raise(status: int) -> None:
    client, _ = _client({BASE: _FakeResponse(status, {})})

    with pytest.raises(HackerOneError):
        client.structured_scopes("acme")


def test_invalid_handle_rejected() -> None:
    client = HackerOneClient("h", "t", session=_FakeSession({}))

    with pytest.raises(HackerOneError):
        client.structured_scopes("acme/../etc")
