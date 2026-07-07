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

import http.client
import re
import socket
import ssl
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

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
    ("nginx", "http"),
    ("apache", "apache"),
    ("apache", "http"),
    ("php", "php"),
    ("php", "http"),
    ("werkzeug", "werkzeug"),
    ("werkzeug", "http"),
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
_REDIRECT_URL_RE = re.compile(r"https?://[^\s\"'<>),]+")
_HTTP_REDIRECT_PORTS = {80, 443, 8000, 8080, 8443}


# ── dataclasses ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ServiceBanner:
    """One open port and its version banner."""

    port: int
    proto: str
    product: str
    version: str
    raw: str  # e.g. "nginx 1.22.0"
    redirect_locations: tuple[str, ...] = ()


@dataclass(frozen=True)
class Surface:
    """Detected attack surface for one host."""

    host: str
    open_ports: tuple[int, ...]
    services: tuple[ServiceBanner, ...]
    tech: tuple[str, ...]  # playbook-vocabulary tokens
    vhosts: tuple[str, ...] = ()

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
        redirect_locations = _nmap_redirect_locations(port_el, svc_el)
        if svc_el is None:
            banners.append(
                ServiceBanner(
                    port=portid,
                    proto=proto,
                    product="",
                    version="",
                    raw="",
                    redirect_locations=redirect_locations,
                )
            )
            continue

        product = svc_el.get("product", "")
        version = svc_el.get("version", "")
        extra = svc_el.get("extrainfo", "")
        raw = " ".join(p for p in (product, version, extra) if p).strip()
        banners.append(
            ServiceBanner(
                port=portid,
                proto=proto,
                product=product,
                version=version,
                raw=raw,
                redirect_locations=redirect_locations,
            )
        )

    return _surface_from_banners(host, banners)


def _surface_from_banners(host: str, banners: list[ServiceBanner]) -> Surface:
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
        open_ports=tuple(sorted({b.port for b in banners})),
        services=tuple(banners),
        tech=tuple(sorted(tech_set)),
        vhosts=_vhosts_from_locations(
            host, (location for b in banners for location in b.redirect_locations)
        ),
    )


def _extract_redirect_locations(text: str) -> tuple[str, ...]:
    lowered = text.lower()
    if "redirect" not in lowered and "location" not in lowered:
        return ()
    locations: list[str] = []
    for match in _REDIRECT_URL_RE.finditer(text):
        location = match.group(0).rstrip(".,;")
        if location not in locations:
            locations.append(location)
    return tuple(locations)


def _nmap_redirect_locations(
    port_el: ET.Element,
    svc_el: ET.Element | None,
) -> tuple[str, ...]:
    texts: list[str] = []
    if svc_el is not None:
        texts.extend(svc_el.attrib.values())
    for script_el in port_el.iter("script"):
        output = script_el.get("output")
        if output:
            texts.append(output)
    for elem_el in port_el.iter("elem"):
        if elem_el.text:
            texts.append(elem_el.text)

    locations: list[str] = []
    for text in texts:
        for location in _extract_redirect_locations(text):
            if location not in locations:
                locations.append(location)
    return tuple(locations)


def _normalize_hostname(host: str) -> str:
    normalized = host.strip().rstrip(".").lower()
    if normalized.startswith("[") and normalized.endswith("]"):
        return normalized[1:-1]
    return normalized


def _vhost_from_location(location: str, target_host: str) -> str | None:
    parsed = urlparse(location.strip())
    hostname = parsed.hostname
    if hostname is None:
        return None
    vhost = _normalize_hostname(hostname)
    if not vhost or vhost == _normalize_hostname(target_host):
        return None
    return vhost


def _vhosts_from_locations(target_host: str, locations: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    vhosts: list[str] = []
    for location in locations:
        vhost = _vhost_from_location(location, target_host)
        if vhost is None or vhost in seen:
            continue
        seen.add(vhost)
        vhosts.append(vhost)
    return tuple(vhosts)


def _surface_with_additional_vhosts(surface: Surface, vhosts: Iterable[str]) -> Surface:
    combined: list[str] = []
    for vhost in (*surface.vhosts, *vhosts):
        if vhost not in combined:
            combined.append(vhost)
    return replace(surface, vhosts=tuple(combined))


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


def _parse_port_text(port_text: str) -> int | None:
    try:
        port = int(port_text)
    except ValueError:
        return None
    return port if 1 <= port <= 65535 else None


def _extract_target_port(target: str) -> int | None:
    if "://" in target:
        parsed = urlparse(target)
        try:
            return parsed.port
        except ValueError:
            return None
    if target.startswith("["):
        end = target.find("]")
        suffix = target[end + 1 :] if end != -1 else ""
        return _parse_port_text(suffix[1:]) if suffix.startswith(":") else None
    if target.count(":") != 1:
        return None
    port_part = target.rsplit(":", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    return _parse_port_text(port_part)


def _explicit_ports(ports: str) -> set[int]:
    selected: set[int] = set()
    for part in ports.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start = _parse_port_text(start_text.strip())
            end = _parse_port_text(end_text.strip())
            if start is not None and end is not None and start <= end:
                selected.update(range(start, end + 1))
            continue
        port = _parse_port_text(token)
        if port is not None:
            selected.add(port)
    return selected


def _fallback_ports(ports: str, target_port: int | None) -> list[int]:
    from bugbounty_ctf.playbook import load_tracks

    selected: set[int]
    if ports not in {"top", "all"}:
        selected = _explicit_ports(ports)
    else:
        selected = set()
        for track in load_tracks():
            selected.update(track.ports)
    if target_port is not None:
        selected.add(target_port)
    return sorted(selected)


def _new_http_connection(host: str, port: int) -> http.client.HTTPConnection:
    if port in {443, 8443}:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, port, timeout=1.0, context=context)
    return http.client.HTTPConnection(host, port, timeout=1.0)


def _http_service_banner(host: str, port: int) -> ServiceBanner | None:
    conn = _new_http_connection(host, port)
    try:
        conn.request("GET", "/")
        response = conn.getresponse()
        server = response.getheader("Server", "")
        location = response.getheader("Location", "") if 300 <= response.status < 400 else ""
        response.read()
    except (OSError, http.client.HTTPException):
        return None
    finally:
        conn.close()
    product, version = _split_server_header(server)
    raw = " ".join(part for part in (product, version) if part).strip()
    return ServiceBanner(
        port=port,
        proto="tcp",
        product=product,
        version=version,
        raw=raw,
        redirect_locations=(location,) if location else (),
    )


def _split_server_header(server: str) -> tuple[str, str]:
    first = server.strip().split(" ", 1)[0]
    if not first:
        return "http", ""
    product, separator, version = first.partition("/")
    return product or "http", version if separator else ""


def _fallback_surface(host: str, ports: str = "top", target_port: int | None = None) -> Surface:
    scan_ports = _fallback_ports(ports, target_port)
    open_ports = _tcp_connect_scan(host, ports=scan_ports, timeout=1.0)

    banners: list[ServiceBanner] = []
    for port in open_ports:
        banner = _http_service_banner(host, port)
        banners.append(
            banner or ServiceBanner(port=port, proto="tcp", product="", version="", raw="")
        )
    return _surface_from_banners(host, banners)


def _looks_http_service(service: ServiceBanner) -> bool:
    key = f"{service.product} {service.raw}".lower()
    return service.port in _HTTP_REDIRECT_PORTS or any(
        marker in key for marker in ("http", "nginx", "apache", "iis", "tomcat", "caddy")
    )


def _probe_http_vhosts(surface: Surface) -> Surface:
    locations: list[str] = []
    for service in surface.services:
        if not _looks_http_service(service):
            continue
        banner = _http_service_banner(surface.host, service.port)
        if banner is not None:
            locations.extend(banner.redirect_locations)
    return _surface_with_additional_vhosts(surface, _vhosts_from_locations(surface.host, locations))


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
    target_port = _extract_target_port(target)

    # Build nmap argv
    argv = ["nmap", "-sV", "-Pn", "-oX", "-"]
    if target_port is not None and ports == "top":
        argv += ["-p", str(target_port)]
    elif ports == "top":
        argv += ["--top-ports", "1000"]
    elif ports == "all":
        argv += ["-p-"]
    else:
        argv += ["-p", ports]
    argv.append(host)

    try:
        result = exec_env.run(argv, timeout=float(timeout))
        if result.returncode == 0 and result.stdout.strip():
            surface = _parse_nmap_xml(result.stdout, host=host)
            # Enrich vhosts with a direct HTTP redirect probe. nmap -sV only
            # notes a redirect sometimes; the probe catches the common
            # IP->vhost 301 (e.g. HTB boxes) regardless. Best-effort: it uses
            # short timeouts and never raises, so it is safe on the nmap-success
            # path too — not just the fallback.
            return _probe_http_vhosts(surface)
    except Exception:
        pass

    # nmap unavailable or failed — stdlib TCP fallback
    return _fallback_surface(host, ports=ports, target_port=target_port)


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
        suffix = fname[len(full_prefix) :]
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
