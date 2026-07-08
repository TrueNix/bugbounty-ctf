"""Tests for recon.py — surface auto-detection from a bare target.

All tests are pure-unit: no network, no docker, no kalibox.  The real
nmap/connect-scan execution path is covered via env-injection spies and
monkeypatches so CI runs cleanly without any live infrastructure.
"""

from __future__ import annotations

import socket
import subprocess
import threading
from collections.abc import Sequence
from typing import Any

# ---------------------------------------------------------------------------
# Shared nmap XML fixture — represents a typical -sV -oX scan of a small target
# ---------------------------------------------------------------------------

NMAP_XML_SIMPLE = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -Pn -oX - 10.10.10.5" version="7.94"
         xmloutputversion="1.05">
  <host starttime="1700000000" endtime="1700000010">
    <status state="up" reason="echo-reply"/>
    <address addr="10.10.10.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.22.0" extrainfo=""/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="8.0.32" extrainfo=""/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_PHP = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.10.10.6" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.56" extrainfo="PHP/8.1.10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_NFS = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.10.10.7" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="111">
        <state state="open" reason="syn-ack"/>
        <service name="rpcbind" product="rpcbind" version="2-4" extrainfo=""/>
      </port>
      <port protocol="tcp" portid="2049">
        <state state="open" reason="syn-ack"/>
        <service name="nfs" product="NFS" version="3-4" extrainfo=""/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_NO_VERSIONS = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.10.10.8" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_XML_REDIRECT = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" xmloutputversion="1.05">
  <host>
    <status state="up" reason="echo-reply"/>
    <address addr="10.129.43.132" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.22.0"
                 servicefp="Did not follow redirect to https://fireflow.htb/"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


# ---------------------------------------------------------------------------
# Fake ExecEnv — never touches docker/kalibox
# ---------------------------------------------------------------------------


class SpyEnv:
    """ExecEnv spy: records argv calls and returns canned XML output.

    If ``nmap_xml`` is set the first nmap call returns it; otherwise it
    returns a non-zero rc to simulate nmap-absent (triggers the fallback path).
    """

    def __init__(self, nmap_xml: str | None = None) -> None:
        self.nmap_xml = nmap_xml
        self.calls: list[list[str]] = []

    def run(
        self, argv: Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        if argv and argv[0] == "nmap" and self.nmap_xml is not None:
            return subprocess.CompletedProcess(argv, 0, stdout=self.nmap_xml, stderr="")
        # nmap absent or not-nmap call → fail so caller can branch
        return subprocess.CompletedProcess(argv, 1, stdout="", stderr="command not found")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNmapXmlParsing:
    """Test 1: XML fixture → correct ports / services / versions."""

    def test_ports_extracted(self) -> None:
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        assert set(surface.open_ports) == {22, 80, 3306}

    def test_products_extracted(self) -> None:
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        products = {s.product.lower() for s in surface.services}
        assert "nginx" in products
        assert "openssh" in products

    def test_versions_extracted(self) -> None:
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        version_map = {s.port: s.version for s in surface.services}
        assert version_map[80] == "1.22.0"
        assert version_map[3306] == "8.0.32"

    def test_host_preserved(self) -> None:
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        assert surface.host == "10.10.10.5"


class TestTechMapping:
    """Test 2: service products → playbook tech vocabulary."""

    def test_nginx_maps_to_web_track(self) -> None:
        from bugbounty_ctf import playbook
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        tracks = playbook.select(ports=surface.open_ports, tech=surface.tech)
        ids = [t.id for t in tracks]
        assert "web" in ids

    def test_apache_php_maps_to_web_track(self) -> None:
        from bugbounty_ctf import playbook
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_PHP, host="10.10.10.6")
        tracks = playbook.select(ports=surface.open_ports, tech=surface.tech)
        ids = [t.id for t in tracks]
        assert "web" in ids

    def test_nfs_ports_map_to_nfs_track(self) -> None:
        from bugbounty_ctf import playbook
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_NFS, host="10.10.10.7")
        tracks = playbook.select(ports=surface.open_ports, tech=surface.tech)
        ids = [t.id for t in tracks]
        assert "nfs" in ids


class TestVersionBanner:
    """Test 3: any product+version → "version-banner" emitted → cve track fires."""

    def test_versioned_service_emits_version_banner(self) -> None:
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        assert "version-banner" in surface.tech

    def test_version_banner_fires_cve_track(self) -> None:
        from bugbounty_ctf import playbook
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        tracks = playbook.select(ports=surface.open_ports, tech=surface.tech)
        ids = [t.id for t in tracks]
        assert "cve" in ids

    def test_no_product_no_version_banner(self) -> None:
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_NO_VERSIONS, host="10.10.10.8")
        assert "version-banner" not in surface.tech


class TestSurfaceForRun:
    """Test 4: Surface.for_run() shape."""

    def test_returns_list_int_and_list_str(self) -> None:
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        ports_out, tech_out = surface.for_run()
        assert isinstance(ports_out, list)
        assert all(isinstance(p, int) for p in ports_out)
        assert isinstance(tech_out, list)
        assert all(isinstance(t, str) for t in tech_out)

    def test_for_run_passes_to_playbook_select(self) -> None:
        from bugbounty_ctf import playbook
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_SIMPLE, host="10.10.10.5")
        ports_out, tech_out = surface.for_run()
        # Should not raise — correct types accepted
        tracks = playbook.select(ports=ports_out, tech=tech_out)
        assert isinstance(tracks, list)


class TestSurfaceServiceVersions:
    def test_surface_service_versions_shape(self) -> None:
        from bugbounty_ctf.recon import ServiceBanner, Surface

        surface = Surface(
            host="10.10.10.5",
            open_ports=(22, 80, 443, 8080),
            services=(
                ServiceBanner(22, "tcp", "OpenSSH", "", "OpenSSH"),
                ServiceBanner(80, "tcp", "nginx", "1.22.0", "nginx 1.22.0"),
                ServiceBanner(443, "tcp", "", "3.0.2", "3.0.2"),
                ServiceBanner(8080, "tcp", "Apache httpd", "2.4.56", "Apache httpd 2.4.56"),
            ),
            tech=("version-banner",),
        )

        assert surface.service_versions() == [
            {"product": "nginx", "version": "1.22.0"},
            {"product": "Apache httpd", "version": "2.4.56"},
        ]


class TestVhostRedirectCapture:
    def test_surface_captures_vhost_from_redirect(self, monkeypatch: Any) -> None:
        from bugbounty_ctf import recon

        class RedirectResponse:
            status = 301

            def getheader(self, name: str, default: str = "") -> str:
                headers = {"Server": "nginx/1.22.0", "Location": "https://fireflow.htb/"}
                return headers.get(name, default)

            def read(self) -> bytes:
                return b""

        class RedirectConnection:
            def __init__(self, host: str, port: int, timeout: float, **kwargs: Any) -> None:
                self.host = host
                self.port = port
                self.timeout = timeout

            def request(self, method: str, path: str) -> None:
                assert method == "GET"
                assert path == "/"

            def getresponse(self) -> RedirectResponse:
                return RedirectResponse()

            def close(self) -> None:
                return None

        monkeypatch.setattr(recon, "_tcp_connect_scan", lambda *args, **kwargs: [443])
        monkeypatch.setattr(recon.http.client, "HTTPConnection", RedirectConnection)
        monkeypatch.setattr(recon.http.client, "HTTPSConnection", RedirectConnection)

        surface = recon.detect_surface("10.129.43.132:443", ports="443", env=SpyEnv())

        assert surface.vhosts == ("fireflow.htb",)

    def test_surface_no_vhost_when_no_redirect(self, monkeypatch: Any) -> None:
        from bugbounty_ctf import recon

        class OkResponse:
            status = 200

            def getheader(self, name: str, default: str = "") -> str:
                return "nginx/1.22.0" if name == "Server" else default

            def read(self) -> bytes:
                return b""

        class OkConnection:
            def __init__(self, host: str, port: int, timeout: float, **kwargs: Any) -> None:
                self.host = host
                self.port = port
                self.timeout = timeout

            def request(self, method: str, path: str) -> None:
                assert method == "GET"
                assert path == "/"

            def getresponse(self) -> OkResponse:
                return OkResponse()

            def close(self) -> None:
                return None

        monkeypatch.setattr(recon, "_tcp_connect_scan", lambda *args, **kwargs: [80])
        monkeypatch.setattr(recon.http.client, "HTTPConnection", OkConnection)

        surface = recon.detect_surface("10.129.43.132:80", ports="80", env=SpyEnv())

        assert surface.vhosts == ()

    def test_vhost_dedup_and_excludes_target_host(self) -> None:
        from bugbounty_ctf.recon import ServiceBanner, _surface_from_banners

        surface = _surface_from_banners(
            "10.129.43.132",
            [
                ServiceBanner(
                    443,
                    "tcp",
                    "nginx",
                    "1.22.0",
                    "nginx 1.22.0",
                    (
                        "https://10.129.43.132/",
                        "https://fireflow.htb/",
                        "https://FireFlow.HTB./",
                    ),
                ),
            ],
        )

        assert surface.vhosts == ("fireflow.htb",)

    def test_parse_nmap_xml_extracts_vhost_from_redirect_note(self) -> None:
        from bugbounty_ctf.recon import _parse_nmap_xml

        surface = _parse_nmap_xml(NMAP_XML_REDIRECT, host="10.129.43.132")

        assert surface.vhosts == ("fireflow.htb",)


class TestFallbackTcpConnect:
    """Test 5: when nmap is absent, fall back to TCP connect-scan."""

    def test_fallback_finds_local_listener(self, tmp_path: Any) -> None:
        """Start a real local listener, confirm fallback returns its port."""
        from bugbounty_ctf.recon import _tcp_connect_scan

        # Bind a listener on an ephemeral port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        srv.listen(5)

        def _accept() -> None:
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                pass
            finally:
                srv.close()

        t = threading.Thread(target=_accept, daemon=True)
        t.start()

        try:
            open_ports = _tcp_connect_scan("127.0.0.1", ports=[port], timeout=2.0)
            assert port in open_ports
        finally:
            srv.close()
            t.join(timeout=3)

    def test_closed_port_not_reported(self) -> None:
        from bugbounty_ctf.recon import _tcp_connect_scan

        # Port 1 is almost certainly not listening and needs no privilege on
        # Linux for connect() (just returns ECONNREFUSED).
        open_ports = _tcp_connect_scan("127.0.0.1", ports=[1], timeout=0.5)
        assert 1 not in open_ports


class TestEnvInjection:
    """Test 6: nmap invocation flows through the injected ExecEnv, never bare subprocess."""

    def test_nmap_called_via_env(self) -> None:
        from bugbounty_ctf.recon import detect_surface

        spy = SpyEnv(nmap_xml=NMAP_XML_SIMPLE)
        surface = detect_surface("10.10.10.5", env=spy)
        # Env was called
        assert spy.calls, "env.run() was never called"
        # The first call was nmap
        assert spy.calls[0][0] == "nmap"
        # Surface has the expected ports
        assert 80 in surface.open_ports

    def test_nmap_not_called_without_env_injection(self, monkeypatch: Any) -> None:
        """When env raises on nmap, detect_surface must NOT fall back to a raw host call."""
        from bugbounty_ctf.recon import detect_surface

        raw_calls: list[str] = []
        original_run = subprocess.run

        def spy_run(argv: Any, **kw: Any) -> Any:
            if isinstance(argv, (list, tuple)) and argv and argv[0] == "nmap":
                raw_calls.append(str(argv))
            return original_run(argv, **kw)

        spy = SpyEnv(nmap_xml=NMAP_XML_SIMPLE)
        monkeypatch.setattr(subprocess, "run", spy_run)
        # With env injected the host subprocess.run must not see nmap
        detect_surface("10.10.10.5", env=spy)
        assert not raw_calls, f"detect_surface called host nmap directly: {raw_calls}"


class TestDeadEndFeedback:
    """Part B: empty-findings fan-out track → dead-end recorded → recalled on recon guidance."""

    def test_dead_end_written_to_kb(self, tmp_path: Any) -> None:
        from bugbounty_ctf.knowledge import KnowledgeBase
        from bugbounty_ctf.recon import record_dead_end

        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(tmp_path))
        added = record_dead_end(kb, host="10.10.10.5", track_id="mail", reason="no open ports")
        assert added

    def test_dead_end_not_duplicated(self, tmp_path: Any) -> None:
        from bugbounty_ctf.knowledge import KnowledgeBase
        from bugbounty_ctf.recon import record_dead_end

        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(tmp_path))
        record_dead_end(kb, host="10.10.10.5", track_id="nfs", reason="empty findings")
        added_again = record_dead_end(
            kb, host="10.10.10.5", track_id="nfs", reason="empty findings"
        )
        assert not added_again, "duplicate dead-end must be de-duplicated"

    def test_dead_ends_recalled_in_guidance(self, tmp_path: Any) -> None:
        from bugbounty_ctf.knowledge import KnowledgeBase
        from bugbounty_ctf.recon import list_dead_ends, record_dead_end

        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(tmp_path))
        record_dead_end(kb, host="10.10.10.5", track_id="mail", reason="no MX ports open")
        dead = list_dead_ends(kb, host="10.10.10.5")
        assert any(d["track_id"] == "mail" for d in dead)

    def test_clear_dead_end_removes_record(self, tmp_path: Any) -> None:
        from bugbounty_ctf.knowledge import KnowledgeBase
        from bugbounty_ctf.recon import clear_dead_end, list_dead_ends, record_dead_end

        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(tmp_path))
        record_dead_end(kb, host="10.10.10.5", track_id="mail", reason="no findings")

        assert clear_dead_end(kb, host="10.10.10.5", track_id="mail")
        assert list_dead_ends(kb, host="10.10.10.5") == []

    def test_consecutive_failure_counter_increments_on_record_resets_on_clear(
        self, tmp_path: Any
    ) -> None:
        from bugbounty_ctf.knowledge import KnowledgeBase
        from bugbounty_ctf.recon import (
            clear_dead_end,
            get_consecutive_failures,
            record_dead_end,
        )

        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(tmp_path))

        record_dead_end(kb, host="10.10.10.5", track_id="web", reason="spdy failed")
        record_dead_end(kb, host="10.10.10.5", track_id="web", reason="spdy failed")
        record_dead_end(kb, host="10.10.10.6", track_id="web", reason="spdy failed")

        assert get_consecutive_failures(kb, host="10.10.10.5", track_id="web") == 2
        assert get_consecutive_failures(kb, host="10.10.10.6", track_id="web") == 1

        clear_dead_end(kb, host="10.10.10.5", track_id="web")

        assert get_consecutive_failures(kb, host="10.10.10.5", track_id="web") == 0
        assert get_consecutive_failures(kb, host="10.10.10.6", track_id="web") == 1

    def test_hot_dead_ends_filtered_at_threshold(self, tmp_path: Any) -> None:
        from bugbounty_ctf.knowledge import KnowledgeBase
        from bugbounty_ctf.recon import list_hot_dead_ends, record_dead_end

        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(tmp_path))
        for _ in range(3):
            record_dead_end(kb, host="10.10.10.5", track_id="web", reason="spdy failed")
        record_dead_end(kb, host="10.10.10.5", track_id="mail", reason="no auth")
        for _ in range(3):
            record_dead_end(kb, host="10.10.10.6", track_id="web", reason="spdy failed")

        hot = list_hot_dead_ends(kb, host="10.10.10.5", threshold=3)

        assert [entry["track_id"] for entry in hot] == ["web"]
        assert hot[0]["consecutive_failures"] == 3

    def test_clear_is_idempotent(self, tmp_path: Any) -> None:
        from bugbounty_ctf.knowledge import KnowledgeBase
        from bugbounty_ctf.recon import clear_dead_end

        kb = KnowledgeBase(db_path=str(tmp_path / "test.db"), references_dir=str(tmp_path))

        assert not clear_dead_end(kb, host="10.10.10.5", track_id="mail")


def test_recon_dead_end_entrypoints_import_cleanly() -> None:
    import importlib

    recon = importlib.import_module("bugbounty_ctf.recon")
    api = importlib.import_module("bugbounty_ctf.api")

    for name in (
        "detect_surface",
        "record_dead_end",
        "clear_dead_end",
        "get_consecutive_failures",
        "list_hot_dead_ends",
    ):
        assert callable(getattr(recon, name))
        assert callable(getattr(api, name))
