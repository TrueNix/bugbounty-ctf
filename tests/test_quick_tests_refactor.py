from __future__ import annotations

import re
from typing import Any

import requests
import responses

from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.quick_tests import (
    _cmd_analyze,
    _cmd_probe,
    _content_check_path,
    _content_classify,
    _content_probe_paths,
    _cors_analyze,
    _cors_probe_origin,
    _nosqli_analyze,
    _nosqli_probe,
    _path_traversal_analyze,
    _path_traversal_probe,
    _payloads_for_ssti,
    _redirect_analyze,
    _redirect_probe,
    _ssrf_analyze,
    _ssrf_payloads,
    _ssrf_probe,
    _ssti_analyze,
    _ssti_probe_payload,
    discover_content,
    map_surface,
)
from bugbounty_ctf.quick_tests import (
    test_command_injection as run_command_injection,
)
from bugbounty_ctf.quick_tests import (
    test_cors as run_cors,
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
    test_open_redirect as run_open_redirect,
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


def _scanner() -> SecurityScanner:
    return SecurityScanner("http://target.test/", db=ScannerDB(":memory:"))


class _QueuedScanner(SecurityScanner):
    def __init__(
        self,
        queued: list[requests.Response] | None = None,
        surface: dict[str, Any] | None = None,
    ) -> None:
        super().__init__("http://target.test/", db=ScannerDB(":memory:"))
        self.queued = queued or []
        self.surface = surface or {}
        self.calls: list[dict[str, Any]] = []

    def _make_request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        if self.queued:
            return self.queued.pop(0)
        return _response(200, "same")

    def map_surface(self, start_path: str) -> dict[str, Any]:
        self.calls.append({"method": "MAP", "url": start_path, "kwargs": {}})
        return self.surface


def _response(status: int, text: str, headers: dict[str, str] | None = None) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = text.encode()
    response.headers.update(headers or {})
    response.response_time = 0.0
    return response


def _probe_record(
    name: str,
    payload: Any,
    baseline: requests.Response,
    response: requests.Response,
) -> dict[str, Any]:
    return {"name": name, "payload": payload, "baseline": baseline, "response": response}


def test_content_probe_paths_builds_expected_set() -> None:
    paths = _content_probe_paths(
        "http://target.test/",
        wordlist=[" admin ", "/api", "", "  "],
        extensions=["php", ".bak"],
        limit=-1,
    )
    assert paths == ["admin", "admin.php", "admin.bak", "api", "api.php", "api.bak"]


def test_login_sqli_no_change_returns_empty_results() -> None:
    scanner = _QueuedScanner([_response(200, "Login failed") for _ in range(6)])
    assert run_login_sqli("http://target.test/login", scanner=scanner) == []


@responses.activate
def test_content_check_path_classifies_200_as_interesting() -> None:
    responses.add(responses.GET, "http://target.test/admin", body="admin panel", status=200)
    result = _content_check_path("http://target.test/admin", _scanner())
    assert result is not None
    assert result["path"] == "admin"
    assert result["status"] == 200
    assert result["length"] == len("admin panel")


@responses.activate
def test_content_check_path_classifies_404_as_empty() -> None:
    responses.add(responses.GET, "http://target.test/missing", body="not found", status=404)
    assert _content_check_path("http://target.test/missing", _scanner()) is None


def test_content_classify_marks_zero_status_empty() -> None:
    classified = _content_classify(_response(0, "Request failed"))
    assert classified["empty"] is True
    assert classified["status"] == 0


@responses.activate
def test_cors_probe_origin_sends_header() -> None:
    responses.add(
        responses.GET,
        "http://target.test/api",
        body="ok",
        status=200,
        match=[responses.matchers.header_matcher({"Origin": "https://evil.example"})],
    )
    probe = _cors_probe_origin("http://target.test/api", "https://evil.example", _scanner())
    assert probe["response"].status_code == 200
    assert responses.calls[0].request.headers["Origin"] == "https://evil.example"


def test_cors_analyze_detects_wildcard_misconfig() -> None:
    analysis = _cors_analyze(
        {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
        "https://evil.example",
    )
    assert analysis["reflected"] is True
    assert analysis["severity"] == "high"
    assert analysis["note"] == "wildcard ACAO with credentials"


def test_cors_analyze_detects_null_origin() -> None:
    analysis = _cors_analyze({"Access-Control-Allow-Origin": "null"}, "null")
    assert analysis["reflected"] is True
    assert analysis["severity"] == "medium"
    assert analysis["note"] == "null origin trusted"


def test_cors_analyze_detects_reflection_without_credentials() -> None:
    analysis = _cors_analyze(
        {"Access-Control-Allow-Origin": "https://evil.example"},
        "https://evil.example",
    )
    assert analysis["reflected"] is True
    assert analysis["severity"] == "medium"
    assert analysis["note"] == "attacker origin reflected (no credentials)"


@responses.activate
def test_redirect_probe_captures_location() -> None:
    responses.add(
        responses.GET,
        "http://target.test/login",
        headers={"Location": "https://evil.example"},
        status=302,
    )
    probe = _redirect_probe("http://target.test/login", "https://evil.example", _scanner())
    assert probe["response"].headers["Location"] == "https://evil.example"
    assert probe["param"] == "next"


def test_redirect_analyze_classifies_open_redirect() -> None:
    result = _redirect_analyze(
        _response(302, "", {"Location": "https://evil.example"}),
        "https://evil.example",
        "evil.example",
        param="next",
        payload_type="absolute",
    )
    assert result["open"] is True
    assert result["param"] == "next"
    assert result["payload_type"] == "absolute"


@responses.activate
def test_ssrf_probe_sends_payload() -> None:
    payload = "http://169.254.169.254/latest/meta-data/"
    responses.add(
        responses.POST,
        "http://target.test/fetch",
        body="metadata",
        status=200,
        match=[responses.matchers.urlencoded_params_matcher({"url": payload})],
    )
    probe = _ssrf_probe("http://target.test/fetch", "url", payload, _scanner())
    assert probe["response"].status_code == 200
    assert probe["payload"] == payload


def test_ssrf_payloads_append_suffix() -> None:
    payloads = _ssrf_payloads("#.yaml")
    assert payloads["aws_metadata"].endswith("/#.yaml")
    assert payloads["localhost"] == "http://127.0.0.1#.yaml"


def test_ssrf_analyze_detects_filter_behavior() -> None:
    results = _ssrf_analyze(
        [
            _probe_record(
                "localhost", "http://127.0.0.1", _response(200, "ok"), _response(403, "blocked")
            )
        ]
    )
    assert results[0]["payload"] == "localhost"
    assert "status_code_change" in results[0]["analysis"]["indicators"]


@responses.activate
def test_ssti_probe_sends_payload() -> None:
    payload = "{{7*7}}"
    responses.add(
        responses.POST,
        "http://target.test/render",
        body="49",
        status=200,
        match=[responses.matchers.urlencoded_params_matcher({"template": payload})],
    )
    probe = _ssti_probe_payload(
        "http://target.test/render", "POST", "template", payload, _scanner()
    )
    assert probe["response"].text == "49"
    assert probe["payload"] == payload


def test_ssti_payloads_expand_all_engines() -> None:
    payloads = _payloads_for_ssti(True)
    assert payloads["jinja2_math_7x49"] == "{{7*49}}"
    assert payloads["erb_rce_test"] == "<%= `id` %>"


def test_ssti_reports_7x49_confirmation(capsys: Any) -> None:
    scanner = _QueuedScanner(
        [
            _response(200, "Template test"),
            _response(200, "Template test"),
            _response(200, "Template 343"),
            _response(200, "Template test"),
            _response(200, "Template test"),
            _response(200, "Template test"),
        ]
    )
    results = run_ssti("http://target.test/render", scanner=scanner)
    assert any(result["payload"] == "math_7x49" for result in results)
    assert "7*49 evaluated to 343" in capsys.readouterr().out


def test_ssti_analyze_detects_evaluation() -> None:
    results = _ssti_analyze(
        [
            _probe_record(
                "math_7x7", "{{7*7}}", _response(200, "Template test"), _response(200, "49")
            )
        ]
    )
    assert results[0]["payload"] == "math_7x7"
    assert "ssti_evaluated" in results[0]["analysis"]["indicators"]


@responses.activate
def test_cmd_probe_sends_payload() -> None:
    responses.add(
        responses.GET,
        "http://target.test/ping",
        body="uid=1000(root)",
        status=200,
        match=[responses.matchers.query_param_matcher({"input": "; id"})],
    )
    probe = _cmd_probe("http://target.test/ping", "GET", "input", "; id", _scanner())
    assert probe["response"].text == "uid=1000(root)"


@responses.activate
def test_cmd_probe_sends_post_payload() -> None:
    responses.add(
        responses.POST,
        "http://target.test/ping",
        body="uid=1000(root)",
        status=200,
        match=[responses.matchers.urlencoded_params_matcher({"input": "; id"})],
    )
    probe = _cmd_probe("http://target.test/ping", "POST", "input", "; id", _scanner())
    assert probe["response"].status_code == 200


def test_cmd_analyze_detects_output() -> None:
    results = _cmd_analyze(
        [
            _probe_record(
                "semicolon_id", "; id", _response(200, "ping"), _response(200, "uid=0 gid=0")
            )
        ]
    )
    assert results[0]["payload"] == "semicolon_id"
    assert "command_output" in results[0]["analysis"]["indicators"]


@responses.activate
def test_path_traversal_probe_and_analyze() -> None:
    payload = "../../../etc/passwd"
    responses.add(
        responses.GET,
        "http://target.test/download",
        body="root:x:0:0:root:/root:/bin/bash",
        status=200,
        match=[responses.matchers.query_param_matcher({"file": payload})],
    )
    probe = _path_traversal_probe("http://target.test/download", "GET", "file", payload, _scanner())
    results = _path_traversal_analyze(
        [_probe_record("passwd_1", payload, _response(404, "not found"), probe["response"])]
    )
    assert results[0]["payload"] == "passwd_1"
    assert "file_contents" in results[0]["analysis"]["indicators"]


@responses.activate
def test_path_traversal_probe_sends_post_payload() -> None:
    payload = "../../../etc/passwd"
    responses.add(
        responses.POST,
        "http://target.test/download",
        body="root:x:0:0:root:/root:/bin/bash",
        status=200,
        match=[responses.matchers.urlencoded_params_matcher({"file": payload})],
    )
    probe = _path_traversal_probe(
        "http://target.test/download", "POST", "file", payload, _scanner()
    )
    assert probe["response"].status_code == 200


def test_path_traversal_post_baseline_can_return_empty() -> None:
    scanner = _QueuedScanner([_response(200, "same") for _ in range(5)])
    assert run_path_traversal("http://target.test/download", method="POST", scanner=scanner) == []


@responses.activate
def test_nosqli_probe_and_analyze() -> None:
    payload = {"username": {"$ne": None}, "password": "x"}
    responses.add(
        responses.POST,
        "http://target.test/login",
        json={"logged_in": True},
        status=200,
        match=[responses.matchers.json_params_matcher(payload)],
    )
    probe = _nosqli_probe("http://target.test/login", "username", "password", payload, _scanner())
    results = _nosqli_analyze(
        [_probe_record("ne_null_username", payload, _response(401, "invalid"), probe["response"])]
    )
    assert results[0]["payload"] == "ne_null_username"
    assert "status_code_change" in results[0]["analysis"]["indicators"]


def test_nosqli_interesting_without_auth_text(capsys: Any) -> None:
    scanner = _QueuedScanner(
        [
            _response(401, "invalid"),
            _response(500, "server error"),
            _response(401, "invalid"),
            _response(401, "invalid"),
            _response(401, "invalid"),
            _response(401, "invalid"),
        ]
    )
    results = run_nosqli("http://target.test/login", scanner=scanner)
    assert results[0]["payload"] == "ne_null_username"
    assert "AUTH BYPASS CONFIRMED" not in capsys.readouterr().out


def test_ldap_no_change_returns_empty_results() -> None:
    scanner = _QueuedScanner([_response(401, "Login failed") for _ in range(4)])
    assert run_ldap_injection("http://target.test/login", scanner=scanner) == []


def test_map_surface_prints_link_overflow(capsys: Any) -> None:
    surface = {
        "status_code": 200,
        "tech_hints": [],
        "forms": [],
        "links": [f"http://target.test/{index}" for index in range(21)],
    }
    result = map_surface("http://target.test/", scanner=_QueuedScanner(surface=surface))
    assert result["links"] == surface["links"]
    assert "... and 1 more" in capsys.readouterr().out


@responses.activate
def test_error_handling_returns_graceful_on_connection_error() -> None:
    responses.add(
        responses.GET,
        re.compile(r"http://target\.test/.*"),
        body=requests.exceptions.ConnectionError("boom"),
    )
    responses.add(
        responses.POST,
        re.compile(r"http://target\.test/.*"),
        body=requests.exceptions.ConnectionError("boom"),
    )

    assert run_ssti("http://target.test/render", method="GET") == []
    assert run_command_injection("http://target.test/ping", method="GET") == []
    assert run_path_traversal("http://target.test/download", method="GET") == []
    assert run_ssrf("http://target.test/fetch", method="GET") == []
    assert run_nosqli("http://target.test/login") == []
    assert run_cors("http://target.test/api") == []
    assert run_open_redirect("http://target.test/login", params=["next"]) == []
    assert discover_content("http://target.test/", wordlist=["admin"], workers=1) == []


@responses.activate
def test_discover_content_handles_all_404() -> None:
    responses.add(responses.GET, "http://target.test/admin", body="not found", status=404)
    responses.add(responses.GET, "http://target.test/missing", body="not found", status=404)
    results = discover_content(
        "http://target.test/",
        wordlist=["admin", "missing"],
        workers=1,
        limit=-1,
    )
    assert results == []


@responses.activate
def test_discover_content_handles_mixed_responses() -> None:
    responses.add(responses.GET, "http://target.test/admin", body="admin panel", status=200)
    responses.add(responses.GET, "http://target.test/forbidden", body="forbidden", status=403)
    responses.add(responses.GET, "http://target.test/missing", body="not found", status=404)
    results = discover_content(
        "http://target.test/",
        wordlist=["admin", "forbidden", "missing"],
        workers=1,
        limit=-1,
    )
    assert [result["path"] for result in results] == ["admin", "forbidden"]
