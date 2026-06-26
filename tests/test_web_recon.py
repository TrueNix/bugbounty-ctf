"""Tests for web_recon.py — verifies the shell injection fix."""

from __future__ import annotations

from bugbounty_ctf.web_recon import recon_report, run_cmd


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
