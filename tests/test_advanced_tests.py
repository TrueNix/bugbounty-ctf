from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qs, unquote_plus, urlparse

import pytest
import requests
import responses

import bugbounty_ctf.advanced_tests as advanced
from bugbounty_ctf.advanced_tests import (
    ChainContext,
    detect_defenses,
    detect_ssrf_filter,
    generate_aws_presigned_url,
    generate_report,
    graphql_field_dump,
    graphql_introspection,
    save_report,
)
from bugbounty_ctf.advanced_tests import (
    test_file_upload as run_file_upload,
)
from bugbounty_ctf.advanced_tests import (
    test_jwt_attacks as run_jwt_attacks,
)
from bugbounty_ctf.advanced_tests import (
    test_pickle_deserialization as run_pickle_deserialization,
)
from bugbounty_ctf.advanced_tests import (
    test_xxe as run_xxe,
)
from bugbounty_ctf.advanced_tests import (
    test_yaml_deserialization as run_yaml_deserialization,
)
from bugbounty_ctf.engine import SecurityScanner


def _body_text(request: requests.PreparedRequest) -> str:
    body = request.body or b""
    if isinstance(body, bytes):
        return body.decode("latin1", errors="ignore")
    return str(body)


def _json_response(payload: dict[str, object]) -> tuple[int, dict[str, str], bytes]:
    return (200, {"Content-Type": "application/json"}, json.dumps(payload).encode())


class TestDetectDefenses:
    @responses.activate
    def test_detects_waf_rate_limit_and_missing_security_headers(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)
        calls = {"count": 0}

        def callback(_request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            calls["count"] += 1
            headers = {"Server": "cloudflare", "X-Sucuri-ID": "abc"}
            if calls["count"] >= 6:
                return (429, headers, b"rate limited")
            return (403, headers, b"request blocked by cloudflare")

        responses.add_callback(responses.GET, "http://target/", callback=callback)

        result = detect_defenses("http://target/", paths=["/"])

        assert result["waf"] in {
            "Cloudflare",
            "Generic",
            "Generic WAF (status-based detection)",
            "Sucuri",
        }
        assert result["rate_limit"].startswith("Triggered after")
        assert result["security_headers"]["Content-Security-Policy"] == "MISSING"
        assert any("likely blocked" in item for item in result["evidence"])

    @responses.activate
    def test_clean_response_stays_quiet(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)
        security_headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "same-origin",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "0",
            "Server": "nginx",
        }

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            query = parse_qs(urlparse(request.url).query)
            body = query.get("q", ["ok"])[0]
            return (200, security_headers, body.encode())

        responses.add_callback(responses.GET, "http://target/", callback=callback)

        result = detect_defenses("http://target/", paths=["/"])

        assert result["waf"] is None
        assert result["rate_limit"] == "No 429 in 20 burst requests"
        assert result["input_filters"] == []
        assert "MISSING" not in result["security_headers"].values()


class TestXxe:
    @responses.activate
    def test_confirms_file_and_php_filter_reflection(self) -> None:
        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            body = _body_text(request)
            if "php://filter" in body:
                return (200, {}, b"cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA==")
            if "file:///etc/passwd" in body:
                return (200, {}, b"root:x:0:0:root:/root:/bin/bash")
            return (200, {}, b"<root>hello</root>")

        responses.add_callback(responses.POST, "http://target/xml", callback=callback)

        results = run_xxe("http://target/xml")
        by_payload = {item["payload"]: item for item in results}

        assert by_payload["external_passwd"]["confirmed"] is True
        assert by_payload["php_filter_b64"]["confirmed"] is True

    @responses.activate
    def test_clean_parser_ignores_external_entities(self) -> None:
        responses.add(responses.POST, "http://target/xml", body="<root>hello</root>", status=200)

        results = run_xxe("http://target/xml")

        assert all(item["confirmed"] is False for item in results)


def _create_marker_from_payload(request: requests.PreparedRequest, marker: dict[str, Path]) -> None:
    decoded = unquote_plus(_body_text(request))
    match = re.search(r"touch\s+(/tmp/[A-Za-z0-9_]+)", decoded)
    if match:
        marker["path"] = Path(match.group(1))
    if path := marker.get("path"):
        path.touch()


class TestDeserialization:
    @responses.activate
    def test_pickle_marker_creation_is_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        marker: dict[str, Path] = {}
        monkeypatch.setattr(advanced.time, "time", lambda: 1_700_000_000.0)
        monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            _create_marker_from_payload(request, marker)
            return (200, {}, b"DRTBP_DESERIAL_MARKER")

        responses.add_callback(responses.POST, "http://target/pickle", callback=callback)

        results = run_pickle_deserialization("http://target/pickle")

        assert any(item["confirmed"] is True for item in results)

    @responses.activate
    def test_pickle_ignored_payload_is_clean(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(advanced.time, "time", lambda: 1_700_000_001.0)
        monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)
        responses.add(responses.POST, "http://target/pickle", body="ignored", status=200)

        results = run_pickle_deserialization("http://target/pickle")

        assert all(item["confirmed"] is False for item in results)

    @responses.activate
    def test_yaml_marker_creation_is_detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        marker: dict[str, Path] = {}
        monkeypatch.setattr(advanced.time, "time", lambda: 1_700_000_002.0)
        monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            _create_marker_from_payload(request, marker)
            return (200, {}, b"yaml marker")

        responses.add_callback(responses.POST, "http://target/yaml", callback=callback)

        results = run_yaml_deserialization("http://target/yaml")

        assert any(item["confirmed"] is True for item in results)

    @responses.activate
    def test_yaml_ignored_payload_is_clean(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(advanced.time, "time", lambda: 1_700_000_003.0)
        monkeypatch.setattr(advanced.time, "sleep", lambda _seconds: None)
        responses.add(responses.POST, "http://target/yaml", body="ignored", status=200)

        results = run_yaml_deserialization("http://target/yaml")

        assert all(item["confirmed"] is False for item in results)


class TestJwtAttacks:
    @responses.activate
    def test_bruteforces_weak_hs256_secret_and_attempts_alg_none(self) -> None:
        payload = {"sub": "user-1", "role": "user"}
        token = advanced.forge_jwt_hs256(payload, "secret")
        escalated = {"sub": "user-1", "role": "admin", "is_admin": True, "admin": True}
        accepted = advanced.forge_jwt_hs256(escalated, "secret")
        seen_algs: list[str] = []

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            probe = request.headers["Authorization"].removeprefix("Bearer ")
            decoded = advanced.decode_jwt(probe)
            if decoded is not None and "error" not in decoded:
                seen_algs.append(decoded["header"]["alg"])
            if probe == accepted:
                return (200, {}, b'{"role":"admin","dashboard":true}')
            return (401, {}, b"unauthorized")

        responses.add_callback(responses.GET, "http://target/admin", callback=callback)

        result = run_jwt_attacks("http://target/profile", token, verify_endpoint="http://target/admin")

        assert result["decoded"]["payload"]["sub"] == "user-1"
        assert seen_algs[0] == "none"
        assert result["none_accepted"] is False
        assert result["weak_secret"] == "secret"

    @responses.activate
    def test_returns_clean_result_when_forged_tokens_are_rejected(self) -> None:
        token = advanced.forge_jwt_hs256({"sub": "user-1", "role": "user"}, "strong-secret")
        responses.add(responses.GET, "http://target/admin", body="unauthorized", status=401)

        result = run_jwt_attacks("http://target/profile", token, verify_endpoint="http://target/admin")

        assert result["none_accepted"] is False
        assert result["hs256_empty_accepted"] is False
        assert result["weak_secret"] is None


class TestFileUpload:
    @responses.activate
    def test_phtml_bypass_is_accepted_and_rce_verified(self) -> None:
        def upload_callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            if "shell.phtml" in _body_text(request):
                return (201, {}, b'{"file":"http://target/uploads/shell.phtml"}')
            return (400, {}, b'{"error":"extension rejected"}')

        responses.add_callback(responses.POST, "http://target/upload", callback=upload_callback)
        responses.add(responses.GET, "http://target/uploads/shell.phtml", body="uid=33(www-data)")

        results = run_file_upload("http://target/upload")
        phtml = next(item for item in results if item["payload"] == "phtml")

        assert phtml["accepted"] is True
        assert phtml["rce_confirmed"] is True
        assert phtml["stored_at"] == "http://target/uploads/shell.phtml"

    @responses.activate
    def test_rejected_uploads_are_clean(self) -> None:
        responses.add(responses.POST, "http://target/upload", body='{"error":"rejected"}', status=400)

        results = run_file_upload("http://target/upload")

        assert all(item["accepted"] is False for item in results)
        assert all(item["rce_confirmed"] is False for item in results)


class TestGraphqlHelpers:
    @responses.activate
    def test_introspection_and_field_dump_parse_schema(self) -> None:
        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            body = json.loads(_body_text(request))
            query = body["query"]
            if "__schema" in query:
                return _json_response(
                    {
                        "data": {
                            "__schema": {
                                "types": [
                                    {"name": "Query", "kind": "OBJECT", "fields": []},
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
                        }
                    }
                )
            return _json_response(
                {
                    "data": {
                        "__type": {
                            "name": "AdminSecret",
                            "kind": "OBJECT",
                            "fields": [
                                {"name": "flag", "type": {"name": "String"}, "args": []}
                            ],
                            "inputFields": [],
                            "enumValues": [],
                        }
                    }
                }
            )

        responses.add_callback(responses.POST, "http://target/graphql", callback=callback)

        schema = graphql_introspection("http://target/graphql")
        fields = graphql_field_dump("http://target/graphql", "AdminSecret")

        assert schema["introspection_enabled"] is True
        assert schema["type_count"] == 2
        assert schema["interesting_types"][0]["type"] == "AdminSecret"
        assert fields["fields"][0]["name"] == "flag"

    @responses.activate
    def test_introspection_disabled_errors_are_graceful(self) -> None:
        responses.add(
            responses.POST,
            "http://target/graphql",
            json={"errors": [{"message": "Introspection is disabled"}]},
            status=200,
        )

        schema = graphql_introspection("http://target/graphql")
        fields = graphql_field_dump("http://target/graphql", "AdminSecret")

        assert schema["introspection_enabled"] is False
        assert "disabled" in schema["error"].lower()
        assert fields["error"] == "type not found"


class TestChainContext:
    @responses.activate
    def test_token_reaches_admin_endpoint_and_helpers_record_state(self) -> None:
        context = ChainContext()
        context.add_token("admin", "TOKEN123", source="login")
        context.add_credential("alice", "password", source="leak")
        context.add_finding("idor", "/api/users/2", "read another user")

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            if request.headers.get("Authorization") == "Bearer TOKEN123":
                return (200, {}, b"admin panel " + (b"x" * 110))
            return (401, {}, b"unauthorized")

        responses.add_callback(responses.GET, "http://target/admin", callback=callback)

        without_token = context.session.get("http://target/admin")
        results = context.try_endpoints_with_token("admin", ["/admin"], "http://target")

        assert without_token.status_code == 401
        assert results == [
            {
                "endpoint": "/admin",
                "header": {"Authorization": "Bearer TOKEN123"},
                "status": 200,
                "length": 122,
            }
        ]
        assert context.tokens["admin"] == "TOKEN123"
        assert context.credentials[0]["user"] == "alice"
        assert any(item["type"] == "idor" for item in context.findings)


class TestReporting:
    def test_markdown_orders_by_severity_and_save_round_trips(self, tmp_path: Path) -> None:
        findings = [
            {
                "type": "open_redirect",
                "endpoint": "/next",
                "method": "GET",
                "payload": "url=https://evil.test",
                "indicators": ["redirect"],
                "details": ["redirected offsite"],
            },
            {
                "type": "rce",
                "endpoint": "/debug",
                "method": "POST",
                "payload": "id",
                "indicators": ["command_output"],
                "details": ["uid=33(www-data)"],
            },
            {
                "type": "xxe",
                "endpoint": "/xml",
                "method": "POST",
                "payload": "external_passwd",
                "indicators": ["xxe_triggered"],
                "details": ["/etc/passwd reflected"],
            },
        ]

        markdown = generate_report(findings, target="http://target")
        md_path = Path(save_report(findings, str(tmp_path / "report.md")))
        json_path = Path(save_report(findings, str(tmp_path / "report.json"), format="json"))
        saved_json = json.loads(json_path.read_text())

        assert markdown.find("CRITICAL") < markdown.find("HIGH") < markdown.find("LOW")
        assert "uid=33(www-data)" in markdown
        assert "/etc/passwd reflected" in markdown
        assert "redirected offsite" in markdown
        assert "command_output" in md_path.read_text()
        assert saved_json["findings_count"] == 3
        assert [item["type"] for item in saved_json["findings"]] == ["open_redirect", "rce", "xxe"]


class TestSsrfAndAws:
    @responses.activate
    def test_detect_ssrf_filter_identifies_decimal_bypass(self) -> None:
        scanner = SecurityScanner("http://target", state_file=":memory:")
        payloads = [
            {"name": "localhost", "url": "http://127.0.0.1", "bypasses": "none"},
            {"name": "decimal", "url": "http://2130706433", "bypasses": "127.0.0.1_filter"},
        ]

        def callback(request: requests.PreparedRequest) -> tuple[int, dict[str, str], bytes]:
            body = unquote_plus(_body_text(request))
            if "127.0.0.1" in body:
                return (200, {}, b"blocked by SSRF filter")
            return (200, {}, b"metadata response")

        responses.add_callback(responses.POST, "http://target/fetch", callback=callback)

        result = detect_ssrf_filter(
            "http://target",
            scanner,
            payloads,
            ssrf_endpoint="http://target/fetch",
            ssrf_param="url",
        )

        assert result["blocked"] == ["localhost"]
        assert result["working"] == ["decimal"]
        assert result["bypasses"] == ["decimal"]
        assert "127.0.0.1" in result["blocked_substrings"]

    def test_generate_aws_presigned_url_includes_sigv4_query_params(self) -> None:
        url = generate_aws_presigned_url(
            "sts",
            "GetCallerIdentity",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "session-token",
            region="us-east-1",
        )
        params = parse_qs(urlparse(url).query)

        assert params["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
        assert "X-Amz-Credential" in params
        assert "X-Amz-Date" in params
        assert params["X-Amz-Expires"] == ["3600"]
        assert "X-Amz-SignedHeaders" in params
        assert "X-Amz-Security-Token" in params
        assert "X-Amz-Signature" in params
