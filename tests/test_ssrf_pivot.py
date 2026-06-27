"""Tests for SSRF pivot module."""

from __future__ import annotations

import responses

from bugbounty_ctf.engine import SecurityScanner
from bugbounty_ctf.ssrf_pivot import InternalService, SSRFPivot


class TestInternalService:
    def test_to_dict(self) -> None:
        svc = InternalService(host="0177.0.0.1", port=80, status="open", content_length=200)
        d = svc.to_dict()
        assert d["host"] == "0177.0.0.1"
        assert d["port"] == 80
        assert d["status"] == "open"
        assert d["content_length"] == 200


class TestSSRFPivot:
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

    def test_get_results(self) -> None:
        scanner = SecurityScanner("http://target/", delay=0)
        pivot = SSRFPivot(scanner, "http://target/jobs/preview")
        pivot.services = [InternalService(host="0.0.0.0", port=80)]
        results = pivot.get_results()
        assert len(results) == 1
        assert results[0]["port"] == 80
