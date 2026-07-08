from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
import requests
import responses

import bugbounty_ctf.advanced_tests as advanced
from bugbounty_ctf.engine import SecurityScanner


def _body_text(request: requests.PreparedRequest) -> str:
    body = request.body or b""
    if isinstance(body, bytes):
        return body.decode("latin1", errors="ignore")
    return str(body)


def _response(status: int, body: bytes) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = body
    return response


class TestDefenseHelpers:
    @responses.activate
    def test_header_helpers_detect_waf_and_security_header_state(self) -> None:
        headers = {
            "Server": "cloudflare",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
        }
        responses.add(responses.GET, "http://target/", body="ok", headers=headers)

        result = advanced._detect_waf("http://target/", requests.Session(), paths=[])
        security_headers = advanced._detect_security_headers(result["headers"])

        assert result["waf"] == "Cloudflare"
        assert advanced._detect_csp(result["headers"]) == {
            "Content-Security-Policy": "default-src 'self'"
        }
        assert advanced._detect_hsts(result["headers"]) == {
            "Strict-Transport-Security": "max-age=31536000"
        }
        assert security_headers["X-Frame-Options"] == "DENY"
        assert security_headers["X-Content-Type-Options"] == "MISSING"

    @responses.activate
    def test_rate_limit_helper_reports_first_429(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)
        calls = {"count": 0}

        def callback(_request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            calls["count"] += 1
            if calls["count"] == 3:
                return (429, {}, b"too many")
            return (200, {}, b"ok")

        responses.add_callback(responses.GET, "http://rate/", callback=callback)

        result = advanced._detect_rate_limit("http://rate/", requests.Session())

        assert result["rate_limit"].startswith("Triggered after 3 requests")

    @responses.activate
    def test_input_filter_helper_reports_reflected_transform(self) -> None:
        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            query = parse_qs(urlparse(request.url).query)
            payload = query.get("q", [""])[0]
            return (200, {}, payload.replace("<", "&lt;").encode())

        responses.add_callback(responses.GET, "http://filters/", callback=callback)

        filters = advanced._detect_input_filters("http://filters/", requests.Session())

        assert any(item["char"] == "less_than" for item in filters)


class TestJwtHelpers:
    @responses.activate
    def test_alg_none_helper_reports_accepted_unsigned_token(self) -> None:
        token = advanced.forge_jwt_hs256({"sub": "user-1", "role": "user"}, "secret")

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            probe = request.headers["Authorization"].removeprefix("Bearer ")
            decoded = advanced.decode_jwt(probe)
            if decoded is not None and decoded.get("header", {}).get("alg") == "none":
                return (200, {}, b"admin dashboard")
            return (401, {}, b"unauthorized")

        responses.add_callback(responses.GET, "http://jwt/none", callback=callback)

        result = advanced._jwt_alg_none_attack(
            token, "http://jwt/none", "Authorization", requests.Session()
        )

        assert result["none_accepted"] is True
        assert advanced.decode_jwt(result["none"])["header"]["alg"] == "none"

    @responses.activate
    def test_hs256_empty_helper_reports_empty_secret_acceptance(self) -> None:
        token = advanced.forge_jwt_hs256({"sub": "user-1", "role": "user"}, "secret")
        expected = advanced.forge_jwt_hs256(
            {"sub": "user-1", "role": "admin", "is_admin": True, "admin": True}, ""
        )

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            probe = request.headers["Authorization"].removeprefix("Bearer ")
            if probe == expected:
                return (200, {}, b'{"role":"admin"}')
            return (401, {}, b"unauthorized")

        responses.add_callback(responses.GET, "http://jwt/empty", callback=callback)

        result = advanced._jwt_hs256_empty_attack(
            token, "http://jwt/empty", "Authorization", requests.Session()
        )

        assert result["hs256_empty_accepted"] is True
        assert result["hs256_empty"] == expected

    @responses.activate
    def test_weak_secret_helper_returns_matching_secret(self) -> None:
        token = advanced.forge_jwt_hs256({"sub": "user-1", "role": "user"}, "secret")
        expected = advanced.forge_jwt_hs256(
            {"sub": "user-1", "role": "admin", "is_admin": True, "admin": True}, "secret"
        )

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            probe = request.headers["Authorization"].removeprefix("Bearer ")
            if probe == expected:
                return (200, {}, b"administrator dashboard")
            return (401, {}, b"unauthorized")

        responses.add_callback(responses.GET, "http://jwt/weak", callback=callback)

        result = advanced._jwt_weak_secret_attack(
            token, "http://jwt/weak", "Authorization", requests.Session()
        )

        assert result["weak_secret"] == "secret"


class TestIdorHelpers:
    @responses.activate
    def test_baseline_and_compare_helpers_mark_distinct_id_response(self) -> None:
        url_template = "http://target/api/users/{ID}/profile"
        responses.add(
            responses.GET,
            "http://target/api/users/1/profile",
            json={"user": "alice"},
            status=200,
        )
        responses.add(
            responses.GET,
            "http://target/api/users/2/profile",
            json={"user": "bob"},
            status=200,
        )
        for user_id in range(3, 51):
            responses.add(
                responses.GET,
                f"http://target/api/users/{user_id}/profile",
                json={"user": "alice"},
                status=200,
            )

        scanner = SecurityScanner("http://target", state_file=":memory:")
        baseline = advanced._idor_baseline(url_template, scanner)
        comparisons = advanced._idor_compare(baseline, scanner)

        assert baseline[0]["status"] == 200
        assert comparisons[0]["distinct_response"]["id"] == 2


class TestXxeHelpers:
    @responses.activate
    def test_external_entity_helper_returns_external_payload_results(self) -> None:
        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            body = _body_text(request)
            if "php://filter" in body:
                return (200, {}, b"cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA==")
            if "file:///etc/passwd" in body:
                return (200, {}, b"root:x:0:0:root:/root:/bin/bash")
            return (200, {}, b"<root>hello</root>")

        responses.add_callback(responses.POST, "http://target/xml", callback=callback)

        result = advanced._xxe_external_entity(
            "http://target/xml", "POST", "application/xml", requests.Session()
        )

        by_payload = {item["payload"]: item for item in result["results"]}
        assert by_payload["external_passwd"]["confirmed"] is True
        assert by_payload["php_filter_b64"]["confirmed"] is True

    @responses.activate
    def test_parameter_injection_helper_returns_parameter_entity_result(self) -> None:
        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            if "ENTITY % file" in _body_text(request):
                return (200, {}, b"root:x:0:0:root:/root:/bin/bash")
            return (200, {}, b"<root>hello</root>")

        responses.add_callback(responses.POST, "http://target/xml", callback=callback)

        result = advanced._xxe_parameter_injection(
            "http://target/xml", "POST", "application/xml", requests.Session()
        )

        assert result["results"][0]["payload"] == "parameter_entity"
        assert result["results"][0]["confirmed"] is True

    @responses.activate
    def test_xxe_helpers_reuse_non_ok_baseline_without_refetching(self) -> None:
        external_calls = {"count": 0}
        parameter_calls = {"count": 0}

        def external_callback(
            _request: requests.PreparedRequest,
        ) -> tuple[int, dict[str, str], bytes]:
            external_calls["count"] += 1
            return (200, {}, b"<root>changed</root>")

        def parameter_callback(
            _request: requests.PreparedRequest,
        ) -> tuple[int, dict[str, str], bytes]:
            parameter_calls["count"] += 1
            return (200, {}, b"<root>changed</root>")

        responses.add_callback(responses.POST, "http://target/external", callback=external_callback)
        responses.add_callback(
            responses.POST, "http://target/parameter", callback=parameter_callback
        )
        baseline = _response(403, b"blocked")

        external = advanced._xxe_external_entity(
            "http://target/external", "POST", "application/xml", requests.Session(), baseline
        )
        parameter = advanced._xxe_parameter_injection(
            "http://target/parameter", "POST", "application/xml", requests.Session(), baseline
        )

        assert external_calls["count"] == 3
        assert parameter_calls["count"] == 1
        assert external["results"][0]["indicators"] == ["status changed: 403→200"]
        assert parameter["results"][0]["indicators"] == ["status changed: 403→200"]


class TestGraphqlHelpers:
    @responses.activate
    def test_batch_query_and_alias_detection_helpers_parse_successes(self) -> None:
        responses.add(
            responses.POST,
            "http://target/graphql",
            json={
                "data": {"m0": {"success": False}, "m1": {"success": True}},
                "errors": [{"message": "schema hint"}],
            },
            status=200,
        )

        scanner = SecurityScanner("http://target", state_file=":memory:")
        query_result = advanced._graphql_batch_query(
            "http://target/graphql",
            "mutation { {ALIASES} }",
            'm0: login(pin:"0000"){success} m1: login(pin:"1337"){success}',
            scanner,
        )
        detection = advanced._graphql_alias_detection(query_result["response"])

        assert query_result["status"] == 200
        assert detection["successes"] == ["m1"]
        assert detection["errors"] == ["schema hint"]

    @responses.activate
    def test_introspection_sender_and_parser_helpers_find_interesting_types(self) -> None:
        schema = {
            "types": [
                {"name": "__Schema", "kind": "OBJECT", "fields": []},
                {
                    "name": "AdminSecret",
                    "kind": "OBJECT",
                    "fields": [{"name": "flag", "type": {"name": "String"}}],
                },
            ],
            "queries": {"name": "Query"},
            "mutations": {"name": "Mutation"},
            "subscriptions": {},
        }
        responses.add(
            responses.POST,
            "http://target/graphql",
            json={"data": {"__schema": schema}},
            status=200,
        )

        scanner = SecurityScanner("http://target", state_file=":memory:")
        result = advanced._graphql_send_introspection("http://target/graphql", scanner)
        interesting = advanced._graphql_parse_schema(result["data"]["data"]["__schema"])

        assert result["status"] == 200
        assert interesting == [
            {"type": "AdminSecret", "fields": ["flag"], "reason": "interesting name"}
        ]


class TestReportHelpers:
    def test_report_helpers_format_finding_and_markdown_sections(self) -> None:
        finding = {
            "type": "rce",
            "endpoint": "/debug",
            "method": "POST",
            "payload": "id",
            "indicators": ["command_output"],
            "details": ["uid=33(www-data)"],
        }

        finding_text = advanced._format_finding_text(finding)
        markdown = advanced._format_report_markdown([finding], "http://target", history=[{}])
        text = advanced._format_report_text([finding], "http://target", history=[{}])

        assert "Finding #1: CRITICAL" in finding_text
        assert finding_text in markdown
        assert "**Tests run:** 1" in markdown
        assert "command_output" in text
