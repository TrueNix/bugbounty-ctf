"""recon — bare target → (ports, tech) surface.

Closes the missing first link in the autonomous harness loop:

    detect_surface(target) → Surface → runner.run(*surface.for_run())

Previously ``SkillOrchestrator.run(ports=, tech=)`` and
``playbook.select(ports, tech)`` both *consumed* port/tech data, but nothing in
the toolkit *produced* it from a bare IP/hostname.  Operators had to run nmap
by hand, parse the output, and build the lists themselves — the serial-in-context
grind the skill explicitly warns against.

This module makes that step automatic:
- Runs ``nmap -sV -Pn -oX -`` inside the default ``KaliEnv`` (no host root).
- Parses the XML output with ``xml.etree.ElementTree`` (stdlib, not grepping
  human text).
- Maps service products to the same tech vocabulary the playbook trigger uses,
  emitting ``"version-banner"`` for any versioned service so the ``cve`` track
  fires automatically.
- Falls back to a plain stdlib TCP connect-scan when nmap is unavailable so
  ``detect_surface`` still returns a usable ``Surface`` offline.
- Exposes ``record_dead_end`` / ``list_dead_ends`` / ``clear_dead_end`` for
  Part B: fan-out tracks that produced no findings can persist that fact so
  re-runs deprioritize them.

Usage::

    from bugbounty_ctf.recon import detect_surface
    from bugbounty_ctf.skill_runner import SkillOrchestrator

    surface = detect_surface("10.10.10.5")
    runner = SkillOrchestrator("http://10.10.10.5/")
    result = runner.run(*surface.for_run())        # zero manual nmap parsing
"""

from __future__ import annotations

import socket
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from bugbounty_ctf.execenv import ExecEnv, default_exec_env

if TYPE_CHECKING:
    from bugbounty_ctf.knowledge import KnowledgeBase

__all__ = [
    "ServiceBanner",
    "Surface",
    "_parse_nmap_xml",
    "_tcp_connect_scan",
    "clear_dead_end",
    "detect_surface",
    "list_dead_ends",
    "record_dead_end",
]

# ── tech-vocabulary mapping ────────────────────────────────────────────────
# Map substrings of nmap product/service names to the tokens playbook.json
# tech triggers use.  Matching is case-insensitive substring, applied in
# order; a product can emit multiple tokens.
_PRODUCT_TO_TECH: list[tuple[str, str]] = [
    ("nginx", "nginx"),
    ("apache", "apache"),
    ("php", "php"),
    ("werkzeug", "werkzeug"),
    ("http", "http"),
    ("iis", "http"),
    ("tomcat", "http"),
    ("lighttpd", "http"),
    ("caddy", "http"),
    ("express", "http"),
    ("openssl", "http"),
]

# Dead-end key prefix — mirrors the learned:: convention in KnowledgeBase.
_DEAD_END_PREFIX = "dead-end::"


# ── dataclasses ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ServiceBanner:
    """One open port and its version banner."""

    port: int
    proto: str
    product: str
    version: str
    raw: str  # e.g. "nginx 1.22.0"


@dataclass(frozen=True)
class Surface:
    """Detected attack surface for one host."""

    host: str
    open_ports: tuple[int, ...]
    services: tuple[ServiceBanner, ...]
    tech: tuple[str, ...]  # playbook-vocabulary tokens

    def for_run(self) -> tuple[list[int], list[str]]:
        """Unpack into (ports, tech) lists for ``runner.run(ports=, tech=)``."""
        return list(self.open_ports), list(self.tech)

    def service_versions(self) -> list[dict[str, str]]:
        return [
            {"product": service.product, "version": service.version}
            for service in self.services
            if service.product and service.version
        ]


# ── XML parser ────────────────────────────────────────────────────────────

def _parse_nmap_xml(xml_text: str, *, host: str) -> Surface:
    """Parse ``nmap -oX`` XML output into a :class:`Surface`.

    Pure function — no I/O, suitable for unit tests with fixture XML.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return Surface(host=host, open_ports=(), services=(), tech=())

    banners: list[ServiceBanner] = []

    for port_el in root.iter("port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        portid = int(port_el.get("portid", 0))
        proto = port_el.get("protocol", "tcp")
        svc_el = port_el.find("service")
        if svc_el is None:
            banners.append(ServiceBanner(port=portid, proto=proto, product="", version="", raw=""))
            continue

        product = svc_el.get("product", "")
        version = svc_el.get("version", "")
        extra = svc_el.get("extrainfo", "")
        raw = " ".join(p for p in (product, version, extra) if p).strip()
        banners.append(ServiceBanner(port=portid, proto=proto, product=product, version=version, raw=raw))

    # Build playbook tech tokens
    tech_set: set[str] = set()
    has_version_banner = False
    for b in banners:
        key = (b.product + " " + b.raw).lower()
        for substr, token in _PRODUCT_TO_TECH:
            if substr in key:
                tech_set.add(token)
        if b.product and b.version:
            has_version_banner = True

    if has_version_banner:
        tech_set.add("version-banner")

    return Surface(
        host=host,
        open_ports=tuple(sorted(b.port for b in banners)),
        services=tuple(banners),
        tech=tuple(sorted(tech_set)),
    )


# ── TCP connect fallback ───────────────────────────────────────────────────

def _tcp_connect_scan(
    host: str,
    *,
    ports: list[int],
    timeout: float = 1.0,
) -> list[int]:
    """Probe ``ports`` with a plain TCP connect; return those that responded.

    No privileges required — just ``socket.connect_ex``.  Used as the nmap
    fallback when the env doesn't have nmap installed.
    """
    open_ports: list[int] = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((host, port))
            s.close()
            if rc == 0:
                open_ports.append(port)
        except OSError:
            pass
    return open_ports


def _fallback_surface(host: str) -> Surface:
    """TCP connect-scan over all playbook trigger ports and return a minimal Surface."""
    from bugbounty_ctf.playbook import load_tracks

    all_ports: set[int] = set()
    for track in load_tracks():
        all_ports.update(track.ports)

    open_ports = _tcp_connect_scan(host, ports=sorted(all_ports), timeout=1.0)

    # Build tech from port membership only (no version info available)
    tech_set: set[str] = set()
    web_ports = {80, 443, 8080, 8000, 8443, 8888}
    if any(p in web_ports for p in open_ports):
        tech_set.add("http")

    return Surface(
        host=host,
        open_ports=tuple(sorted(open_ports)),
        services=(),
        tech=tuple(sorted(tech_set)),
    )


# ── public API ────────────────────────────────────────────────────────────

def detect_surface(
    target: str,
    *,
    ports: str = "top",
    timeout: int = 120,
    env: ExecEnv | None = None,
) -> Surface:
    """Run nmap (in kalibox) and return a :class:`Surface` with open ports and tech.

    Parameters
    ----------
    target:
        IP address or hostname to scan.
    ports:
        ``"top"`` (top 1000, default), ``"all"`` (``-p-``), or a comma-separated
        port list e.g. ``"22,80,443"``.
    timeout:
        Seconds to wait for nmap.
    env:
        Execution environment.  Defaults to ``KaliEnv`` (runs inside the
        disposable Kali container, no host root needed).
    """
    exec_env = env or default_exec_env()
    host = _extract_host(target)

    # Build nmap argv
    argv = ["nmap", "-sV", "-Pn", "-oX", "-"]
    if ports == "top":
        argv += ["--top-ports", "1000"]
    elif ports == "all":
        argv += ["-p-"]
    else:
        argv += ["-p", ports]
    argv.append(host)

    try:
        result = exec_env.run(argv, timeout=float(timeout))
        if result.returncode == 0 and result.stdout.strip():
            return _parse_nmap_xml(result.stdout, host=host)
    except Exception:
        pass

    # nmap unavailable or failed — stdlib TCP fallback
    return _fallback_surface(host)


def _extract_host(target: str) -> str:
    """Strip scheme/path from a target string, returning just the host."""
    if "://" in target:
        # e.g. "http://10.10.10.5/" → "10.10.10.5"
        after_scheme = target.split("://", 1)[1]
        host_part = after_scheme.split("/")[0].split("?")[0].split("#")[0]
        # strip port
        if host_part.startswith("["):
            # IPv6
            end = host_part.find("]")
            return host_part[: end + 1] if end != -1 else host_part
        return host_part.rsplit(":", 1)[0] if ":" in host_part else host_part
    # bare host or host:port
    if target.startswith("["):
        end = target.find("]")
        return target[: end + 1] if end != -1 else target
    return target.rsplit(":", 1)[0] if ":" in target else target


# ── Part B: dead-end feedback ─────────────────────────────────────────────

def record_dead_end(
    kb: KnowledgeBase,
    *,
    host: str,
    track_id: str,
    reason: str = "",
) -> bool:
    """Record that ``track_id`` produced no findings on ``host``.

    Stored as a ``dead-end::<host>::<track_id>`` lesson so future runs can
    deprioritize it.  Returns ``False`` if an identical record already exists
    (de-duplicated by ``KnowledgeBase.add_lesson``).
    """
    title = f"dead-end: {track_id} on {host}"
    body = f"Track '{track_id}' produced no findings on {host}. {reason}".strip()
    key = f"{_DEAD_END_PREFIX}{host}::{track_id}"
    return kb.add_lesson(title, body, tags="dead-end", host=host, key=key)


def clear_dead_end(
    kb: KnowledgeBase,
    *,
    host: str,
    track_id: str,
) -> bool:
    filename = f"{kb.LESSON_PREFIX}{_DEAD_END_PREFIX}{host}::{track_id}"
    cursor = kb.conn.execute("DELETE FROM docs WHERE filename = ?", (filename,))
    kb.conn.commit()
    return cursor.rowcount > 0


def list_dead_ends(
    kb: KnowledgeBase,
    *,
    host: str | None = None,
) -> list[dict[str, Any]]:
    """Return recorded dead-end tracks, optionally filtered by host."""
    lessons = kb.list_lessons()
    # KnowledgeBase.add_lesson stores as "learned::<key>", so the filename is
    # "learned::dead-end::<host>::<track_id>"
    full_prefix = f"{kb.LESSON_PREFIX}{_DEAD_END_PREFIX}"
    results: list[dict[str, Any]] = []
    for lesson in lessons:
        fname = lesson.get("filename", "")
        if not fname.startswith(full_prefix):
            continue
        suffix = fname[len(full_prefix):]
        parts = suffix.split("::", 1)
        le_host = parts[0] if parts else ""
        track_id = parts[1] if len(parts) > 1 else ""
        if host is not None and le_host != host:
            continue
        results.append(
            {
                "host": le_host,
                "track_id": track_id,
                "title": lesson.get("section", ""),
                "body": lesson.get("content", ""),
            }
        )
    return results
