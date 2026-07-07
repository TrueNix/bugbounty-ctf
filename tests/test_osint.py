from __future__ import annotations

import socket
from collections.abc import Mapping

import pytest
import responses

from bugbounty_ctf import osint
from bugbounty_ctf.osint import GOOGLE_DORK_TEMPLATES, OSINTFinding, OSINTToolkit, _extract_flags

DOMAIN = "example.test"
RunResult = tuple[str, str, int]


def _crt_url(domain: str = DOMAIN) -> str:
    return f"https://crt.sh/?q={domain}&output=json"


def _wayback_url(domain: str = DOMAIN) -> str:
    return f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=100"


def _stub_dns(monkeypatch: pytest.MonkeyPatch, resolved: frozenset[str] | None = None) -> None:
    resolved_hosts = resolved or frozenset()

    def gethostbyname(host: str) -> str:
        if host in resolved_hosts:
            return "203.0.113.10"
        raise socket.gaierror

    monkeypatch.setattr(socket, "gethostbyname", gethostbyname)


def _stub_run_cmd(monkeypatch: pytest.MonkeyPatch, results: Mapping[tuple[str, ...], RunResult]) -> None:
    def fake_run_cmd(cmd: list[str], timeout: int = 30) -> RunResult:
        return results.get(tuple(cmd), ("", "", -1))

    monkeypatch.setattr(osint, "_run_cmd", fake_run_cmd)


def test_extract_flags_returns_supported_patterns() -> None:
    text = "HTB{one} flag{two} CTF{three} pwn{four} htb{case_insensitive}"

    flags = set(_extract_flags(text))

    assert flags == {"HTB{one}", "flag{two}", "CTF{three}", "pwn{four}", "htb{case_insensitive}"}


def test_extract_flags_returns_empty_when_absent() -> None:
    assert _extract_flags("nothing useful in this output") == []


@responses.activate
def test_subdomain_enum_dedupes_crt_and_stubbed_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_dns(monkeypatch, frozenset({"dev.example.test"}))
    responses.add(
        responses.GET,
        _crt_url(),
        json=[
            {"name_value": "*.www.example.test\napi.example.test\napi.example.test"},
            {"name_value": "example.test\noutside.invalid"},
        ],
        status=200,
    )
    toolkit = OSINTToolkit()

    subdomains = set(toolkit.subdomain_enum(DOMAIN))

    assert subdomains == {"www.example.test", "api.example.test", "dev.example.test"}
    findings = toolkit.get_findings()
    assert len(findings) == 1
    assert findings[0]["source"] == "subdomain_enum"
    assert findings[0]["details"]["count"] == 3
    assert set(findings[0]["details"]["subdomains"]) == subdomains


@responses.activate
def test_subdomain_enum_returns_empty_when_sources_are_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_dns(monkeypatch)
    responses.add(responses.GET, _crt_url(), json=[], status=200)
    toolkit = OSINTToolkit()

    assert toolkit.subdomain_enum(DOMAIN) == []
    assert toolkit.get_findings() == []


def test_google_dorks_builds_expected_queries_and_finding() -> None:
    toolkit = OSINTToolkit()

    dorks = toolkit.google_dorks(DOMAIN)

    assert len(dorks) == len(GOOGLE_DORK_TEMPLATES)
    assert "site:example.test filetype:pdf" in dorks
    assert "site:example.test inurl:admin" in dorks
    assert 'site:example.test "api key"' in dorks
    assert all("{domain}" not in dork and "other.test" not in dork for dork in dorks)
    finding = toolkit.get_findings()[0]
    assert finding["source"] == "google_dorks"
    assert finding["details"]["dorks"] == dorks

@responses.activate
def test_wayback_lookup_parses_snapshots_and_records_interesting_urls() -> None:
    responses.add(
        responses.GET,
        _wayback_url(),
        json=[
            ["urlkey", "timestamp", "original"],
            ["key", "20240101000000", "https://example.test/admin/config.bak"],
            ["key", "20240202000000", "https://example.test/public"],
        ],
        status=200,
    )
    toolkit = OSINTToolkit()

    results = toolkit.wayback_lookup(DOMAIN)

    assert results == [
        {"url": "https://example.test/admin/config.bak", "timestamp": "20240101000000"},
        {"url": "https://example.test/public", "timestamp": "20240202000000"},
    ]
    findings = toolkit.get_findings()
    assert findings[0]["source"] == "wayback"
    assert findings[0]["details"] == {"interesting_count": 1}


@responses.activate
def test_wayback_lookup_returns_empty_for_malformed_json() -> None:
    responses.add(responses.GET, _wayback_url(), body="not json", content_type="application/json", status=200)
    toolkit = OSINTToolkit()

    assert toolkit.wayback_lookup(DOMAIN) == []
    assert toolkit.get_findings() == []


def test_dns_enum_populates_records_and_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_run_cmd(
        monkeypatch,
        {
            ("dig", "+short", "A", DOMAIN): ("203.0.113.10\n", "", 0),
            ("dig", "+short", "MX", DOMAIN): ("10 mail.example.test.\n", "", 0),
            ("dig", "+short", "NS", DOMAIN): ("ns1.example.test.\nns2.example.test.\n", "", 0),
            ("dig", "+short", "TXT", DOMAIN): ('"v=spf1 include:_spf.example.test"\n"CTF{dns_flag}"\n', "", 0),
        },
    )
    toolkit = OSINTToolkit()

    records = toolkit.dns_enum(DOMAIN)

    assert records == {
        "A": ["203.0.113.10"],
        "MX": ["10 mail.example.test."],
        "NS": ["ns1.example.test.", "ns2.example.test."],
        "TXT": ['"v=spf1 include:_spf.example.test"', '"CTF{dns_flag}"'],
    }
    findings = toolkit.get_findings()
    assert [finding["finding_type"] for finding in findings] == ["dns_records", "flag_in_txt"]
    assert findings[1]["is_flag"] is True
    assert findings[1]["details"]["flags"] == ["CTF{dns_flag}"]


def test_dns_enum_returns_empty_when_tools_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_run_cmd(monkeypatch, {})
    toolkit = OSINTToolkit()

    assert toolkit.dns_enum(DOMAIN) == {}
    assert toolkit.get_findings() == []


@responses.activate
def test_tech_fingerprint_detects_headers_and_cookies() -> None:
    responses.add(
        responses.GET,
        f"https://{DOMAIN}",
        body="<html><script src='/wp-content/app.js'></script></html>",
        headers={
            "Server": "nginx",
            "X-Powered-By": "Express",
            "Set-Cookie": "PHPSESSID=abc123",
        },
        status=200,
    )
    toolkit = OSINTToolkit()

    tech = toolkit.tech_fingerprint(DOMAIN)

    assert tech == {"server": "nginx", "x-powered-by": "Express", "language": "PHP"}
    findings = toolkit.get_findings()
    assert findings[0]["source"] == "tech_fingerprint"
    assert findings[0]["details"] == tech


@responses.activate
def test_tech_fingerprint_returns_empty_for_bare_response() -> None:
    responses.add(responses.GET, f"https://{DOMAIN}", body="<html>plain</html>", status=200)
    toolkit = OSINTToolkit()

    assert toolkit.tech_fingerprint(DOMAIN) == {}
    assert toolkit.get_findings() == []


@responses.activate
def test_enumerate_all_aggregates_stubbed_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_dns(monkeypatch)
    _stub_run_cmd(monkeypatch, {("dig", "+short", "A", DOMAIN): ("203.0.113.10\n", "", 0)})
    responses.add(
        responses.GET,
        _crt_url(),
        json=[{"name_value": "www.example.test"}],
        status=200,
    )
    responses.add(
        responses.GET,
        _wayback_url(),
        json=[
            ["urlkey", "timestamp", "original"],
            ["key", "20240101000000", "https://example.test/secret.env"],
        ],
        status=200,
    )
    responses.add(
        responses.GET,
        f"https://{DOMAIN}",
        headers={"Server": "nginx"},
        status=200,
    )
    toolkit = OSINTToolkit()

    findings = toolkit.enumerate_all(DOMAIN)

    assert {finding.source for finding in findings} == {
        "subdomain_enum",
        "wayback",
        "dns",
        "tech_fingerprint",
    }
    finding_dicts = toolkit.get_findings()
    assert {finding["source"] for finding in finding_dicts} == {
        "subdomain_enum",
        "wayback",
        "dns",
        "tech_fingerprint",
    }
    assert all(
        {"source", "finding_type", "value", "url", "is_flag", "details"} <= finding.keys()
        for finding in finding_dicts
    )


def test_extract_metadata_parses_tool_output_and_flag_strings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_run_cmd(
        monkeypatch,
        {
            ("exiftool", "artifact.pdf"): (
                "Author : Ada\nTitle : Internal runbook\nComment : flag{metadata_field}\n",
                "",
                0,
            ),
            ("strings", "artifact.pdf"): (
                "password=letmein\nhttps://example.test/admin\n/home/ctf/flag.txt\nflag{metadata_flag}\n",
                "",
                0,
            ),
        },
    )
    toolkit = OSINTToolkit()

    metadata = toolkit.extract_metadata("artifact.pdf")

    assert metadata["Author"] == "Ada"
    assert metadata["Title"] == "Internal runbook"
    assert metadata["Comment"] == "flag{metadata_field}"
    assert "password=letmein" in metadata["strings_password"]
    assert "https://example.test/admin" in metadata["strings_url"]
    assert "/home/ctf/flag.txt" in metadata["strings_filepath"]
    findings = toolkit.get_findings()
    assert [finding["finding_type"] for finding in findings] == ["flag_in_file", "file_metadata"]
    assert findings[0]["is_flag"] is True
    assert findings[0]["details"]["flags"] == ["flag{metadata_flag}"]


def test_extract_metadata_returns_empty_when_tools_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_run_cmd(monkeypatch, {})
    toolkit = OSINTToolkit()

    assert toolkit.extract_metadata("missing.bin") == {}
    assert toolkit.get_findings() == []


def test_get_findings_dedupes_and_serializes_seeded_findings() -> None:
    toolkit = OSINTToolkit()
    finding = OSINTFinding(
        source="manual",
        finding_type="note",
        value="duplicate",
        url="https://example.test",
        is_flag=False,
        details={"kind": "seeded"},
    )
    toolkit.findings.extend([finding, finding])

    findings = toolkit.get_findings()

    assert findings == [
        {
            "source": "manual",
            "finding_type": "note",
            "value": "duplicate",
            "url": "https://example.test",
            "is_flag": False,
            "details": {"kind": "seeded"},
        }
    ]
