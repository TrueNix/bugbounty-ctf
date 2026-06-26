"""Tests for quick_tests — SQLi, SSTI, command injection, path traversal."""

from __future__ import annotations

import responses

from bugbounty_ctf.quick_tests import (
    map_surface,
)
from bugbounty_ctf.quick_tests import (
    test_command_injection as run_command_injection,
)
from bugbounty_ctf.quick_tests import (
    test_ldap_injection as run_ldap_injection,
)
from bugbounty_ctf.quick_tests import (
    test_login_sqli as run_login_sqli,
)
from bugbounty_ctf.quick_tests import (
    test_nosqli as run_nosqli,
)
from bugbounty_ctf.quick_tests import (
    test_path_traversal as run_path_traversal,
)
from bugbounty_ctf.quick_tests import (
    test_ssrf as run_ssrf,
)
from bugbounty_ctf.quick_tests import (
    test_ssti as run_ssti,
)


class TestLoginSqli:
    @responses.activate
    def test_sqli_error_detected(self) -> None:
        responses.add(
            responses.POST,
            "http://target/login",
            body="Login failed",
            status=200,
            match=[responses.matchers.urlencoded_params_matcher({"username": "test", "password": "test"})],
        )
        responses.add(
            responses.POST,
            "http://target/login",
            body="SQL syntax error near 'OR 1=1",
            status=500,
            match=[responses.matchers.urlencoded_params_matcher({"username": "'", "password": "anything"})],
        )

        results = run_login_sqli("http://target/login")
        interesting = [r for r in results if r.get("interesting")]
        assert len(interesting) >= 1


class TestSsti:
    @responses.activate
    def test_ssti_confirmed_with_baseline_comparison(self) -> None:
        responses.add(
            responses.POST,
            "http://target/render",
            body="Template rendered: test",
            status=200,
            match=[responses.matchers.urlencoded_params_matcher({"template": "test"})],
        )
        responses.add(
            responses.POST,
            "http://target/render",
            body="Template rendered: 49",
            status=200,
            match=[responses.matchers.urlencoded_params_matcher({"template": "{{7*7}}"})],
        )

        results = run_ssti("http://target/render", method="POST", param_name="template")
        math_result = next(r for r in results if r["payload"] == "math_7x7")
        assert math_result["interesting"] is True


class TestCommandInjection:
    @responses.activate
    def test_command_output_detected(self) -> None:
        responses.add(
            responses.GET,
            "http://target/ping",
            body="ping output",
            status=200,
            match=[responses.matchers.query_param_matcher({"input": "test"})],
        )
        responses.add(
            responses.GET,
            "http://target/ping",
            body="uid=1000(root) gid=1000(root)",
            status=200,
            match=[responses.matchers.query_param_matcher({"input": "; id"})],
        )

        results = run_command_injection("http://target/ping", method="GET", param_name="input")
        interesting = [r for r in results if r.get("interesting")]
        assert len(interesting) >= 1


class TestPathTraversal:
    @responses.activate
    def test_passwd_content_detected(self) -> None:
        responses.add(
            responses.GET,
            "http://target/download",
            body="File not found",
            status=404,
            match=[responses.matchers.query_param_matcher({"file": "test.txt"})],
        )
        responses.add(
            responses.GET,
            "http://target/download",
            body="root:x:0:0:root:/root:/bin/bash",
            status=200,
            match=[responses.matchers.query_param_matcher({"file": "../../../etc/passwd"})],
        )

        results = run_path_traversal("http://target/download", method="GET", param_name="file")
        interesting = [r for r in results if r.get("interesting")]
        assert len(interesting) >= 1


class TestMapSurfaceQuick:
    @responses.activate
    def test_map_surface_returns_forms_and_links(self) -> None:
        html = """
        <html>
        <form action="/search" method="get"><input name="q"></form>
        <a href="/page1">Page 1</a>
        </html>
        """
        responses.add(responses.GET, "http://target/", body=html, status=200)
        surface = map_surface("http://target/")
        assert "forms" in surface
        assert len(surface["forms"]) == 1
        assert "http://target/page1" in surface["links"]


class TestNosqli:
    @responses.activate
    def test_nosqli_auth_bypass_detected(self) -> None:
        responses.add(
            responses.POST,
            "http://target/login",
            json={"error": "invalid credentials"},
            status=401,
        )
        responses.add(
            responses.POST,
            "http://target/login",
            json={"logged_in": True, "user": "admin"},
            status=200,
        )

        results = run_nosqli("http://target/login")
        interesting = [r for r in results if r.get("interesting")]
        assert len(interesting) >= 1


class TestSsrf:
    @responses.activate
    def test_ssrf_metadata_detected(self) -> None:
        responses.add(
            responses.POST,
            "http://target/fetch",
            body="Fetching http://example.com",
            status=200,
            match=[responses.matchers.urlencoded_params_matcher({"url": "http://example.com"})],
        )
        responses.add(
            responses.POST,
            "http://target/fetch",
            body="AccessKeyId: AKIAIOSFODNN7EXAMPLE",
            status=200,
            match=[responses.matchers.urlencoded_params_matcher({"url": "http://169.254.169.254/latest/meta-data/"})],
        )

        results = run_ssrf("http://target/fetch", method="POST", param_name="url")
        interesting = [r for r in results if r.get("interesting")]
        assert len(interesting) >= 1


class TestLdapInjection:
    @responses.activate
    def test_ldap_injection_detected(self) -> None:
        responses.add(
            responses.POST,
            "http://target/login",
            body="Login failed",
            status=401,
            match=[responses.matchers.urlencoded_params_matcher({"username": "test", "password": "test"})],
        )
        responses.add(
            responses.POST,
            "http://target/login",
            body="Login successful! Welcome admin",
            status=200,
            match=[responses.matchers.urlencoded_params_matcher({"username": "*", "password": "*"})],
        )

        results = run_ldap_injection("http://target/login")
        interesting = [r for r in results if r.get("interesting")]
        assert len(interesting) >= 1
