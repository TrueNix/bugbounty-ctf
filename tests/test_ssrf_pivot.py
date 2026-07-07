"""Tests for SSRF pivot module."""

from __future__ import annotations

from collections.abc import Mapping

import responses

from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.ssrf_pivot import InternalService, SSRFPivot


class StubbedSSRFPivot(SSRFPivot):
    def __init__(self, fetches: Mapping[str, str | None] | None = None) -> None:
        scanner = SecurityScanner("http://target/", delay=0)
        super().__init__(scanner, "http://target/jobs/preview")
        self.fetches = dict(fetches or {})
        self.urls: list[str] = []

    def _ssrf_fetch(self, target_url: str) -> str | None:
        self.urls.append(target_url)
        return self.fetches.get(target_url)


class RaisingSSRFPivot(StubbedSSRFPivot):
    def _ssrf_fetch(self, target_url: str) -> str | None:
        self.urls.append(target_url)
        raise RuntimeError("ssrf sink failed")


class TestInternalService:
    def test_to_dict(self) -> None:
        svc = InternalService(host="0177.0.0.1", port=80, status="open", content_length=200)
        d = svc.to_dict()
        assert d["host"] == "0177.0.0.1"
        assert d["port"] == 80
        assert d["status"] == "open"
        assert d["content_length"] == 200


class TestSSRFPivot:
    def test_port_scan_returns_only_open_internal_services(self) -> None:
        pivot = StubbedSSRFPivot(
            {
                "http://10.0.0.5:6379/": "-ERR unknown command\r\n",
                "http://10.0.0.5:9200/": '{"version":{"number":"7.10.0"}}',
                "http://10.0.0.5:8080/": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
                "http://10.0.0.5:8081/": "HTTP/1.1 404 Not Found",
            }
        )

        services = pivot.port_scan("10.0.0.5", ports=[22, 6379, 9200, 8080, 8081])

        assert [(service.host, service.port, service.status) for service in services] == [
            ("10.0.0.5", 6379, "open"),
            ("10.0.0.5", 9200, "open"),
            ("10.0.0.5", 8080, "open"),
            ("10.0.0.5", 8081, "open-404"),
        ]
        assert all(isinstance(service, InternalService) for service in services)

    def test_port_scan_returns_empty_when_all_ports_closed(self) -> None:
        pivot = StubbedSSRFPivot()

        services = pivot.port_scan("10.0.0.5", ports=[22, 80, 443])

        assert services == []
        assert pivot.get_results() == []
        assert pivot.port_scan("10.0.0.5") == []

    def test_fingerprint_services_identifies_internal_service_banners(self) -> None:
        pivot = StubbedSSRFPivot(
            {
                "http://10.0.0.5:6379/": "-ERR unknown command\r\n",
                "http://10.0.0.5:9200/": '{"cluster_name":"ctf","version":{"number":"7.10.0"}}',
                "http://10.0.0.5:80/": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n",
                "http://10.0.0.5:80/flag": "flag{fingerprint_flag}",
                "http://10.0.0.5:3306/": "5.7.31 MySQL Community Server (GPL)",
                "http://10.0.0.5:1234/": "custom tcp banner",
            }
        )
        services = [
            InternalService(host="10.0.0.5", port=6379, status="open"),
            InternalService(host="10.0.0.5", port=9200, status="open"),
            InternalService(host="10.0.0.5", port=80, status="open"),
            InternalService(host="10.0.0.5", port=3306, status="open"),
            InternalService(host="10.0.0.5", port=1234, status="open"),
            InternalService(host="10.0.0.5", port=5555, status="closed"),
        ]
        pivot.services = services

        fingerprinted = pivot.fingerprint_services()

        by_port = {service.port: service for service in fingerprinted}
        assert by_port[6379].service_name == "redis"
        assert by_port[9200].service_name == "elasticsearch"
        assert by_port[9200].version == "7.10.0"
        assert by_port[80].service_name == "http"
        assert by_port[80].version == "nginx/1.24.0"
        assert by_port[3306].service_name == "mysql"
        assert by_port[3306].version == "5.7.31"
        assert by_port[1234].service_name == "unknown"
        assert by_port[80].flags == ["flag{fingerprint_flag}"]
        assert by_port[5555].endpoints == []

    def test_exploit_internal_services_extracts_loot_without_false_positives(self) -> None:
        pivot = StubbedSSRFPivot(
            {
                "http://10.0.0.5:6379/flag": "flag{redis_pivot}",
                "http://10.0.0.5:9200/_search": '{"hit":"HTB{es_loot}"}',
                "http://10.0.0.5:8080/health": '{"status":"ok"}',
            }
        )
        services = [
            InternalService(host="10.0.0.5", port=6379, service_name="redis", endpoints=["/flag"]),
            InternalService(
                host="10.0.0.5",
                port=9200,
                service_name="elasticsearch",
                endpoints=["/_search"],
            ),
            InternalService(host="10.0.0.5", port=8080, service_name="http", endpoints=["/health"]),
        ]

        flags = pivot.exploit_internal_services(services)

        assert flags == ["flag{redis_pivot}", "HTB{es_loot}"]
        assert services[0].flags == ["flag{redis_pivot}"]
        assert services[1].flags == ["HTB{es_loot}"]
        assert services[2].flags == []

    def test_exploit_internal_services_handles_leak_endpoints_without_flags(self) -> None:
        pivot = StubbedSSRFPivot(
            {
                "http://10.0.0.5:8080/.env": "SECRET_KEY=dev",
                "http://10.0.0.5:8080/actuator/env": '{"propertySources":[]}',
                "http://10.0.0.5:8080/api/v1/health": '{"status":"ok"}',
            }
        )
        service = InternalService(
            host="10.0.0.5",
            port=8080,
            endpoints=["/.env", "/actuator/env", "/api/v1/health"],
        )
        empty_service = InternalService(host="10.0.0.5", port=9090)

        flags = pivot.exploit_internal_services([empty_service, service])

        assert flags == []
        assert service.flags == []

    def test_exploit_internal_services_uses_discovered_services_by_default(self) -> None:
        pivot = StubbedSSRFPivot({"http://10.0.0.5:9200/flag": "CTF{auto_path}"})
        pivot.services = [
            InternalService(
                host="10.0.0.5",
                port=9200,
                service_name="elasticsearch",
                endpoints=["/flag"],
            )
        ]

        flags = pivot.exploit_internal_services()

        assert flags == ["CTF{auto_path}"]
        assert pivot.services[0].flags == ["CTF{auto_path}"]

    def test_get_results_includes_scan_and_exploit_state(self) -> None:
        pivot = StubbedSSRFPivot(
            {
                "http://10.0.0.5:8080/": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
                "http://10.0.0.5:8080/flag": "flag{from_results}",
            }
        )
        services = pivot.port_scan("10.0.0.5", ports=[8080])
        services[0].endpoints = ["/flag"]

        flags = pivot.exploit_internal_services()
        results = pivot.get_results()

        assert flags == ["flag{from_results}"]
        assert results == [
            {
                "host": "10.0.0.5",
                "port": 8080,
                "status": "open",
                "content_length": 37,
                "content_preview": "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
                "service_name": "http",
                "version": "nginx/1.24.0",
                "tech_hints": ["nginx"],
                "endpoints": ["/flag"],
                "flags": ["flag{from_results}"],
            }
        ]

    def test_port_scan_degrades_when_fetch_returns_none_or_raises(self) -> None:
        none_pivot = StubbedSSRFPivot()
        raising_pivot = RaisingSSRFPivot()

        assert none_pivot.port_scan("10.0.0.5", ports=[80]) == []
        assert raising_pivot.port_scan("10.0.0.5", ports=[80]) == []

    def test_fingerprint_and_exploit_degrade_when_fetch_raises(self) -> None:
        pivot = RaisingSSRFPivot()
        service = InternalService(host="10.0.0.5", port=8080, status="open", endpoints=["/flag"])

        fingerprinted = pivot.fingerprint_services([service])
        flags = pivot.exploit_internal_services([service])

        assert fingerprinted == [service]
        assert service.flags == []
        assert flags == []

    @responses.activate
    def test_port_scan_finds_open_ports(self) -> None:
        responses.add(responses.GET, "http://target/", body="<html>home</html>", status=200)
        for _ in range(40):
            responses.add(responses.GET, "http://target/", body="<html></html>", status=200)

        def callback(request):
            from urllib.parse import parse_qs

            body = request.body
            if isinstance(body, bytes):
                body = body.decode()
            params = parse_qs(body)
            url = params.get("url", [""])[0]
            if "0177.0.0.1:5000" in url:
                return (200, {"Content-Type": "text/html"}, "<html>Flask app</html>")
            if "0177.0.0.1:9090" in url:
                return (200, {"Content-Type": "text/xml"}, "<xml>STS</xml>")
            if "0177.0.0.1:80" in url:
                return (200, {"Content-Type": "text/html"}, "<html>301 nginx</html>")
            return (200, {}, "Could not fetch URL")

        responses.add_callback(responses.POST, "http://target/jobs/preview", callback=callback)

        scanner = SecurityScanner("http://target/", delay=0)
        pivot = SSRFPivot(
            scanner,
            ssrf_url="http://target/jobs/preview",
            param_name="url",
            method="POST",
            url_suffix="#.yaml",
        )

        services = pivot.port_scan("0177.0.0.1", ports=[80, 5000, 9090, 9999])
        assert len(services) >= 2
        ports = {s.port for s in services}
        assert 5000 in ports
        assert 9090 in ports

    @responses.activate
    def test_port_scan_fingerprinting(self) -> None:
        responses.add(responses.GET, "http://target/", body="<html></html>", status=200)
        for _ in range(40):
            responses.add(responses.GET, "http://target/", body="<html></html>", status=200)

        def callback(request):
            from urllib.parse import parse_qs

            body = request.body
            if isinstance(body, bytes):
                body = body.decode()
            params = parse_qs(body)
            url = params.get("url", [""])[0]
            if "/api/v1/health" in url:
                return (200, {}, '{"status":"ok"}')
            if "0177.0.0.1:5000" in url:
                return (200, {}, "<html>Flask</html>")
            return (200, {}, "Could not fetch URL")

        responses.add_callback(responses.POST, "http://target/jobs/preview", callback=callback)

        scanner = SecurityScanner("http://target/", delay=0)
        pivot = SSRFPivot(
            scanner,
            ssrf_url="http://target/jobs/preview",
            param_name="url",
            method="POST",
        )

        service = InternalService(host="0177.0.0.1", port=5000, status="open-html")
        pivot.services = [service]
        pivot.fingerprint_services([service])
        assert len(service.endpoints) > 0

    def test_extract_flags(self) -> None:
        flags = SSRFPivot._extract_flags("found HTB{test_flag_123} here")
        assert "HTB{test_flag_123}" in flags

    def test_extract_flags_returns_empty_when_absent(self) -> None:
        assert SSRFPivot._extract_flags("no loot here") == []

    def test_get_results(self) -> None:
        scanner = SecurityScanner("http://target/", delay=0)
        pivot = SSRFPivot(scanner, "http://target/jobs/preview")
        pivot.services = [InternalService(host="0.0.0.0", port=80)]
        results = pivot.get_results()
        assert len(results) == 1
        assert results[0]["port"] == 80
