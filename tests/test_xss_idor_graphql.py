"""Tests for XSS, IDOR, and GraphQL alias-batch tests."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import requests
import responses

from bugbounty_ctf.advanced_tests import (
    XSS_PAYLOAD_LADDER,
)
from bugbounty_ctf.advanced_tests import (
    test_graphql_alias_batch as run_graphql_alias_batch,
)
from bugbounty_ctf.advanced_tests import (
    test_idor as run_idor,
)
from bugbounty_ctf.advanced_tests import (
    test_xss as run_xss,
)


class TestXssPayloadLadder:
    """Verify the XSS escalation ladder is properly defined."""

    def test_ladder_has_entries(self) -> None:
        assert len(XSS_PAYLOAD_LADDER) >= 5

    def test_each_entry_has_required_fields(self) -> None:
        for entry in XSS_PAYLOAD_LADDER:
            assert "name" in entry
            assert "payload" in entry
            assert "bypasses" in entry

    def test_ladder_includes_script_tag(self) -> None:
        names = [e["name"] for e in XSS_PAYLOAD_LADDER]
        assert "script_tag" in names


class TestXssDetection:
    @responses.activate
    def test_xss_confirmed_when_payload_reflected_unescaped(self) -> None:
        def reflect_callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            qs = parse_qs(urlparse(request.url).query)
            q_val = qs.get("q", [""])[0]
            body = f"<html>Result: {q_val}</html>"
            return (200, {"Content-Type": "text/html"}, body.encode())

        responses.add_callback(responses.GET, "http://target/search", callback=reflect_callback)

        results = run_xss("http://target/search", method="GET", param_name="q")

        script_result = next(r for r in results if r["payload"] == "script_tag")
        assert script_result["confirmed"] is True

    @responses.activate
    def test_xss_not_confirmed_when_escaped(self) -> None:
        def escape_callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            qs = parse_qs(urlparse(request.url).query)
            q_val = qs.get("q", [""])[0]
            escaped = q_val.replace("<", "&lt;").replace(">", "&gt;")
            body = f"<html>Result: {escaped}</html>"
            return (200, {"Content-Type": "text/html"}, body.encode())

        responses.add_callback(responses.GET, "http://target/search", callback=escape_callback)

        results = run_xss("http://target/search", method="GET", param_name="q")

        script_result = next(r for r in results if r["payload"] == "script_tag")
        assert script_result["confirmed"] is False
        assert script_result["escaped"] is True


class TestIdor:
    @responses.activate
    def test_idor_detected_when_different_content_returned(self) -> None:
        url_template = "http://target/api/users/{ID}/profile"

        # ID=1: user alice
        responses.add(
            responses.GET,
            "http://target/api/users/1/profile",
            json={"user": "alice", "email": "alice@test.com"},
            status=200,
        )
        # ID=2: user bob (different content, same 200)
        responses.add(
            responses.GET,
            "http://target/api/users/2/profile",
            json={"user": "bob", "email": "bob@test.com"},
            status=200,
        )
        # IDs 3-50: same as ID=1 (no IDOR)
        for i in range(3, 51):
            responses.add(
                responses.GET,
                f"http://target/api/users/{i}/profile",
                json={"user": "alice", "email": "alice@test.com"},
                status=200,
            )

        result = run_idor(url_template)

        assert result["summary"]["idor_likely"] is True
        assert result["summary"]["distinct_responses"] == 1

    @responses.activate
    def test_idor_not_detected_when_all_same(self) -> None:
        url_template = "http://target/api/users/{ID}/profile"

        for i in range(1, 51):
            responses.add(
                responses.GET,
                f"http://target/api/users/{i}/profile",
                json={"user": "alice"},
                status=200,
            )

        result = run_idor(url_template)
        assert result["summary"]["idor_likely"] is False


class TestGraphqlAliasBatch:
    @responses.activate
    def test_graphql_returns_success_count(self) -> None:
        # Mock GraphQL endpoint
        responses.add(
            responses.POST,
            "http://target/graphql",
            json={
                "data": {
                    "m0": {"success": False},
                    "m1": {"success": True},
                    "m2": {"success": False},
                    "m3": {"success": False},
                }
            },
            status=200,
        )

        result = run_graphql_alias_batch(
            "http://target/graphql",
            "mutation { {ALIASES} }",
            field_name="login",
            param_name="pin",
            values=["0000", "1111", "1337", "9999"],
        )

        assert result["status"] == 200
        assert result["total_tested"] == 4
        assert len(result["successes"]) == 1
        assert "m1" in result["successes"]

    @responses.activate
    def test_graphql_no_successes(self) -> None:
        responses.add(
            responses.POST,
            "http://target/graphql",
            json={"data": {"m0": {"success": False}}},
            status=200,
        )

        result = run_graphql_alias_batch(
            "http://target/graphql",
            "mutation { {ALIASES} }",
            values=["0000"],
        )

        assert result["successes"] == []
