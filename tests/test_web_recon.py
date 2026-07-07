from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

from bugbounty_ctf import web_recon
from bugbounty_ctf.web_recon import recon_report, recon_target, run_cmd


class TestRunCmd:
    """Verify run_cmd uses argument lists, not shell interpolation."""

    def test_run_cmd_returns_output(self) -> None:
        stdout, _stderr, rc = run_cmd(["echo", "hello"])
        assert rc == 0
        assert stdout == "hello"

    def test_run_cmd_with_arguments(self) -> None:
        stdout, _, rc = run_cmd(["python3", "-c", "print(42)"])
        assert rc == 0
        assert "42" in stdout

    def test_run_cmd_timeout(self) -> None:
        _stdout, stderr, rc = run_cmd(["sleep", "30"], timeout=1)
        assert rc == -1
        assert "TIMEOUT" in stderr

    def test_run_cmd_missing_command(self) -> None:
        _stdout, _stderr, rc = run_cmd(["nonexistent-command-12345"])
        assert rc == -1


class TestReconReport:
    def test_empty_result(self) -> None:
        result = {
            "target": "http://test.com",
            "timestamp": "2026-01-01 00:00:00",
            "quick_mode": False,
            "sections": {},
        }
        report = recon_report(result)
        assert "RECON REPORT" in report
        assert "http://test.com" in report

    def test_error_result(self) -> None:
        result = {
            "target": "http://test.com",
            "timestamp": "2026-01-01 00:00:00",
            "quick_mode": False,
            "sections": {},
            "error": "Invalid URL",
        }
        report = recon_report(result)
        assert "ERROR: Invalid URL" in report

    def test_full_result(self) -> None:
        result = {
            "target": "http://test.com",
            "timestamp": "2026-01-01 00:00:00",
            "quick_mode": False,
            "sections": {
                "technology": {"server": "nginx"},
                "interesting_paths": [{"path": "/admin", "status": "200"}],
                "security_headers": {
                    "present": ["x-frame-options"],
                    "missing": ["CSP missing"],
                },
                "quick_vulns": [{"type": "Directory Listing", "path": "/", "severity": "Low"}],
            },
            "summary": {
                "technology": {"server": "nginx"},
                "security_headers_missing": 1,
                "interesting_paths_found": 1,
                "quick_vulns_found": 1,
            },
        }
        report = recon_report(result)
        assert "TECHNOLOGY" in report
        assert "nginx" in report
        assert "INTERESTING PATHS" in report
        assert "/admin" in report
        assert "SECURITY HEADERS" in report
        assert "QUICK FINDINGS" in report
        assert "Directory Listing" in report


def _install_stub_site(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    commands: list[list[str]] = []
    root_html = """
    <html>
      <head><script src="/static/app.js"></script></head>
      <body>
        <form method="POST" action="/login">
          <input type="hidden" name="csrf" value="token">
          <input name="username">
          <input name="password" type="password">
        </form>
        <a href="/admin">Admin</a>
        <a href="/api">API</a>
        <a href="/docs">Docs</a>
      </body>
    </html>
    """

    def fake_run_cmd(args: list[str], timeout: int = 30) -> tuple[str, str, int]:
        commands.append(args)
        url = args[-1]
        parsed = urlparse(url)
        path = parsed.path or "/"

        if "crt.sh" in url:
            return (json.dumps([{"name_value": "api.example.test\nwww.example.test"}]), "", 0)
        if "-sI" in args:
            headers = "\n".join(
                [
                    "HTTP/1.1 200 OK",
                    "Server: nginx/1.24",
                    "X-Powered-By: Express",
                    "Set-Cookie: csrftoken=abc",
                ]
            )
            return (headers, "", 0)
        if "%{http_code}" in args:
            statuses = {
                "/robots.txt": "200",
                "/sitemap.xml": "404",
                "/admin": "200",
                "/login": "200",
                "/api": "200",
            }
            return (statuses.get(path, "404"), "", 0)
        if path == "/robots.txt":
            return ("User-agent: *\nDisallow: /admin", "", 0)
        if path in {"/", ""}:
            return (root_html, "", 0)
        return ("not found", "", 0)

    monkeypatch.setattr(web_recon, "run_cmd", fake_run_cmd)
    return commands


class TestReconTarget:
    def test_recon_target_extracts_forms_links_scripts_and_report_sections(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _install_stub_site(monkeypatch)

        result = recon_target("http://example.test/", quick=False)
        sections = result["sections"]
        report = recon_report(result)

        assert sections["technology"] == {
            "server": "nginx/1.24",
            "framework": "Django",
        }
        assert sections["forms"][0]["method"] == "POST"
        assert sections["forms"][0]["action"] == "http://example.test:80/login"
        assert [field["name"] for field in sections["forms"][0]["inputs"]] == [
            "csrf",
            "username",
            "password",
        ]
        assert "http://example.test:80/admin" in sections["links"]
        assert "http://example.test:80/api" in sections["links"]
        assert sections["scripts"] == ["http://example.test:80/static/app.js"]
        assert {"path": "/admin", "status": "200"} in sections["interesting_paths"]
        assert set(sections["subdomains"]) == {"api.example.test", "www.example.test"}
        assert "FORMS" in report
        assert "LINKS" in report
        assert "SCRIPTS" in report
        assert "/login" in report

    def test_crafted_path_remains_a_single_safe_command_argument(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        commands = _install_stub_site(monkeypatch)
        marker = tmp_path / "injected"
        target = f"http://example.test/;touch {marker}?q=$(id)"

        result = recon_target(target, quick=True)
        report = recon_report(result)

        assert result["target"] == target
        assert target in report
        assert marker.exists() is False
        assert any(target in command for command in commands)

    def test_unreachable_target_returns_structured_empty_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fake_run_cmd(args: list[str], timeout: int = 30) -> tuple[str, str, int]:
            if "%{http_code}" in args:
                return ("000", "connection failed", -1)
            return ("", "connection failed", -1)

        monkeypatch.setattr(web_recon, "run_cmd", fake_run_cmd)

        result = recon_target("http://offline.test/", quick=True)

        assert result["sections"]["http_headers"] == {}
        assert result["sections"]["interesting_paths"] == []
        assert result["sections"]["quick_vulns"] == []
        assert result["summary"]["interesting_paths_found"] == 0
