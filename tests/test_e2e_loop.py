from __future__ import annotations

import subprocess
import threading
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Final
from urllib.parse import parse_qs, urlparse

import pytest

from bugbounty_ctf import playbook
from bugbounty_ctf.advanced_tests import test_idor as run_idor
from bugbounty_ctf.advanced_tests import test_xss as run_xss
from bugbounty_ctf.engine import ScannerDB, SecurityScanner
from bugbounty_ctf.knowledge import KnowledgeBase
from bugbounty_ctf.recon import Surface, detect_surface, list_dead_ends, record_dead_end
from bugbounty_ctf.skill_runner import SkillOrchestrator

pytestmark: Final = [pytest.mark.integration, pytest.mark.slow]


@dataclass(frozen=True, slots=True)
class LocalTarget:
    base_url: str
    port: int


class _FailingNmapEnv:
    def run(
        self, argv: Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(list(argv), 127, "", "nmap unavailable")


class _VulnerableHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.22.0"
    sys_version = ""

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        match parsed.path:
            case "/":
                self._write_html(
                    HTTPStatus.OK,
                    (
                        '<html><body><form action="/search" method="GET">'
                        '<input name="q" value=""></form>'
                        '<a href="/item?id=1">item</a></body></html>'
                    ),
                )
            case "/search":
                query = parse_qs(parsed.query).get("q", [""])[0]
                self._write_html(HTTPStatus.OK, f"<html><body>Result: {query}</body></html>")
            case "/item":
                item_id = parse_qs(parsed.query).get("id", ["1"])[0]
                owner = "alice" if item_id == "1" else f"user-{item_id}"
                self._write_html(HTTPStatus.OK, f"<html><body>owner={owner}</body></html>")
            case unmatched:
                self._write_html(HTTPStatus.NOT_FOUND, f"missing: {unmatched}")

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write_html(self, status: HTTPStatus, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def local_target() -> Iterator[LocalTarget]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
    host = "127.0.0.1"
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield LocalTarget(base_url=f"http://{host}:{port}", port=port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _scanner_for(target: LocalTarget, tmp_path: Path, name: str) -> SecurityScanner:
    return SecurityScanner(
        target.base_url,
        state_file=str(tmp_path / f"{name}.json"),
        db=ScannerDB(str(tmp_path / f"{name}.db")),
        timeout=1.0,
        delay=0.0,
    )


def _surface_for(target: LocalTarget) -> Surface:
    return detect_surface(f"127.0.0.1:{target.port}", timeout=1, env=_FailingNmapEnv())


def test_detect_surface_finds_local_target(local_target: LocalTarget) -> None:
    # Given: a vulnerable HTTP service on an ephemeral localhost port.
    # When: surface detection falls back to the stdlib TCP scanner.
    surface = _surface_for(local_target)

    # Then: the live port and HTTP/banner-derived tech are available to the loop.
    assert local_target.port in surface.open_ports
    assert {"http", "nginx", "version-banner"} <= set(surface.tech)
    assert any(
        service.port == local_target.port
        and service.product == "nginx"
        and service.version == "1.22.0"
        for service in surface.services
    )


def test_web_track_selected_for_local_surface(local_target: LocalTarget) -> None:
    # Given: a detected live HTTP surface with an nginx version banner.
    surface = _surface_for(local_target)

    # When: the playbook selects tracks for that surface.
    selected = playbook.select(surface.open_ports, surface.tech)
    selected_ids = {track.id for track in selected}

    # Then: web and CVE tracks are wired and their entrypoints import cleanly.
    assert {"web", "cve"} <= selected_ids
    for track in selected:
        assert playbook.resolve_entrypoint(track) is not None


def test_scanner_finds_reflection_and_idor_on_local_target(
    local_target: LocalTarget, tmp_path: Path
) -> None:
    # Given: a real scanner backed by a real temporary SQLite DB.
    scanner = _scanner_for(local_target, tmp_path, "scanner")
    scanner.map_surface("/")

    # When: the scanner-driven quick tests hit the live vulnerable endpoints.
    xss_results = run_xss(f"{local_target.base_url}/search", param_name="q", scanner=scanner)
    idor_result = run_idor(f"{local_target.base_url}/item?id={{ID}}", scanner=scanner)

    # Then: both vulnerabilities are recorded from real localhost HTTP responses.
    assert any(result["payload"] == "script_tag" and result["confirmed"] for result in xss_results)
    assert idor_result["summary"]["idor_likely"] is True
    assert {"xss", "idor"} <= {finding["type"] for finding in scanner.findings}


def test_fan_out_deadend_roundtrip_without_agents(
    local_target: LocalTarget, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a real scanner DB and KB, with a stale dead-end for a now-productive track.
    scanner = _scanner_for(local_target, tmp_path, "fanout")
    scanner.map_surface("/")
    refs = tmp_path / "refs"
    refs.mkdir()
    kb = KnowledgeBase(db_path=str(tmp_path / "kb.db"), references_dir=refs)
    orchestrator = SkillOrchestrator(local_target.base_url, scanner=scanner, knowledge_base=kb)
    record_dead_end(kb, host=scanner.host, track_id="web", reason="previously empty")

    per_label: dict[str, str] = {
        "empty": "<FINDINGS>[]</FINDINGS>",
        "web": (
            '<FINDINGS>[{"type":"xss","endpoint":"/search","method":"GET",'
            '"payload":"script_tag","evidence":"payload reflected","confidence":"high",'
            '"source":"e2e"}]</FINDINGS>'
        ),
    }

    def fake_run(prompt: str, *, timeout: int, label: str = "agent") -> str:
        if local_target.base_url not in prompt or str(scanner.db.db_path) not in prompt:
            raise AssertionError("fan-out prompt lost shared target or ScannerDB path")
        return per_label[label]

    monkeypatch.setattr(orchestrator, "_run_hermes", fake_run)

    # When: fan-out runs one empty and one productive track without spawning Hermes.
    result = orchestrator.fan_out(
        [("empty", "return no findings"), ("web", "report reflected XSS")],
        timeout=1,
        max_workers=2,
    )

    # Then: the dead-end write/clear round-trip is visible in real KB-backed guidance.
    dead_ends = list_dead_ends(kb, host=scanner.host)
    guidance = orchestrator.get_recon_guidance()
    prompt = SkillOrchestrator._build_agent_prompt(guidance)

    assert result["merged"] == 1
    assert result["dead_ends_recorded"] == 1
    assert result["dead_ends_cleared"] == 1
    assert {dead_end["track_id"] for dead_end in dead_ends} == {"empty"}
    assert {dead_end["track_id"] for dead_end in guidance.prior_dead_ends} == {"empty"}
    assert "empty" in prompt
    assert "web" not in {dead_end["track_id"] for dead_end in guidance.prior_dead_ends}
