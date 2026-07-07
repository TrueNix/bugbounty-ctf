"""Tests for HTTP request smuggling module."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from bugbounty_ctf import smuggling
from bugbounty_ctf.smuggling import SmugglingDetector, SmugglingResult

RawResponder = Callable[[bytes], bytes]


def patch_raw_sender(monkeypatch: pytest.MonkeyPatch, responder: RawResponder) -> list[bytes]:
    sent: list[bytes] = []

    def fake_send(_detector: SmugglingDetector, raw: bytes) -> bytes:
        sent.append(raw)
        return responder(raw)

    monkeypatch.setattr(SmugglingDetector, "_send_raw", fake_send)
    return sent


def http_response(
    status: int = 200,
    reason: str = "OK",
    body: str = "",
) -> bytes:
    encoded = body.encode()
    return (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Length: {len(encoded)}\r\n"
        f"\r\n"
    ).encode() + encoded


@pytest.fixture(autouse=True)
def block_real_raw_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(_detector: SmugglingDetector, _raw: bytes) -> bytes:
        raise ConnectionResetError("raw network disabled in tests")

    monkeypatch.setattr(SmugglingDetector, "_send_raw", blocked)


class TestSmugglingResult:
    def test_to_dict(self) -> None:
        result = SmugglingResult(
            vulnerable=True,
            technique="CL.TE",
            evidence="Timeout detected",
            timing_diff=10.0,
        )
        d = result.to_dict()
        assert d["vulnerable"] is True
        assert d["technique"] == "CL.TE"
        assert d["timing_diff"] == 10.0


class TestRawResponseParsing:
    def test_malformed_status_returns_zero(self) -> None:
        assert smuggling._response_status(b"HTTP/1.1\r\n\r\n") == 0
        assert smuggling._response_status(b"HTTP/1.1 nope\r\n\r\n") == 0

    def test_missing_body_separator_returns_empty_body(self) -> None:
        assert smuggling._response_body(b"HTTP/1.1 200 OK") == ""


class TestSmugglingDetector:
    def test_init(self) -> None:
        detector = SmugglingDetector("http://target/")
        assert detector.target_url == "http://target"

    def test_detect_returns_dict(self) -> None:
        detector = SmugglingDetector("http://nonexistent.invalid/")
        results = detector.detect()
        assert "vulnerable" in results
        assert "results" in results
        assert isinstance(results["results"], list)

    def test_exploit_clte_returns_dict(self) -> None:
        detector = SmugglingDetector("http://nonexistent.invalid/")
        result = detector.exploit_clte("/admin", smuggled_body="test=true")
        assert "success" in result

    def test_exploit_store_response_returns_dict(self) -> None:
        detector = SmugglingDetector("http://nonexistent.invalid/")
        result = detector.exploit_store_response("/api/secret")
        assert "success" in result

    def test_detect_aggregates_vulnerable_raw_test(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def responder(raw: bytes) -> bytes:
            if raw.startswith(b"GET / HTTP/1.1"):
                return http_response(400, "Bad Request", "smuggled prefix reached backend")
            return http_response()

        patch_raw_sender(monkeypatch, responder)

        detector = SmugglingDetector("http://target.test/")
        results = detector.detect()

        assert results["vulnerable"] is True
        assert results["technique"] == "CL.TE"
        assert results["results"][0]["vulnerable"] is True

    def test_detect_reports_all_clean_when_raw_tests_are_consistent(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        patch_raw_sender(monkeypatch, lambda _raw: http_response())

        detector = SmugglingDetector("http://target.test/")
        results = detector.detect()

        assert results["vulnerable"] is False
        assert results["technique"] == ""
        assert [result["vulnerable"] for result in results["results"]] == [False, False, False]

    def test_send_raw_failure_marks_inconclusive_without_crashing(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def reset(_raw: bytes) -> bytes:
            raise ConnectionResetError("connection reset by peer")

        patch_raw_sender(monkeypatch, reset)

        result = SmugglingDetector("http://target.test/").test_clte()

        assert result.vulnerable is False
        assert result.details["inconclusive"] is True
        assert result.details["error"] == "connection reset by peer"


class TestHostHeader:
    def test_plain_host(self) -> None:
        assert SmugglingDetector("http://target.test/")._host_header() == "target.test"

    def test_host_with_port(self) -> None:
        assert SmugglingDetector("http://target.test:8080/x")._host_header() == "target.test:8080"

    def test_credentials_are_stripped(self) -> None:
        # The old split("//")[1] leaked user:pass@ into the Host header.
        assert SmugglingDetector("http://user:pass@target.test/")._host_header() == "target.test"

    def test_ipv6_literal_is_bracketed(self) -> None:
        assert SmugglingDetector("http://[::1]:9000/")._host_header() == "[::1]:9000"

    def test_connect_target_defaults_https_port(self) -> None:
        host, port, tls = SmugglingDetector("https://target.test/")._connect_target()
        assert (host, port, tls) == ("target.test", 443, True)

    def test_connect_target_plain_host_defaults_http_port(self) -> None:
        host, port, tls = SmugglingDetector("http://target.test/path")._connect_target()
        assert (host, port, tls) == ("target.test", 80, False)

    def test_connect_target_respects_explicit_port(self) -> None:
        host, port, tls = SmugglingDetector("http://target.test:8080/path")._connect_target()
        assert (host, port, tls) == ("target.test", 8080, False)

    def test_connect_target_ipv6_literal(self) -> None:
        host, port, tls = SmugglingDetector("http://[::1]:8080/")._connect_target()
        assert (host, port, tls) == ("::1", 8080, False)

    def test_connect_target_strips_credentials(self) -> None:
        host, port, tls = SmugglingDetector("https://user:pass@target.test:8443/")._connect_target()
        assert (host, port, tls) == ("target.test", 8443, True)


class TestRawSmugglingDetection:
    def test_clte_detects_probe_anomaly(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def responder(raw: bytes) -> bytes:
            if raw.startswith(b"POST / HTTP/1.1"):
                return http_response()
            return http_response(400, "Bad Request", "smuggled request reached backend")

        sent = patch_raw_sender(monkeypatch, responder)

        result = SmugglingDetector("http://target.test/").test_clte()

        assert result.vulnerable is True
        assert result.technique == "CL.TE"
        assert "response anomaly" in result.evidence
        assert any(b"Content-Length" in raw and b"Transfer-Encoding" in raw for raw in sent)

    def test_clte_reports_clean_for_consistent_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        patch_raw_sender(monkeypatch, lambda _raw: http_response())

        result = SmugglingDetector("http://target.test/").test_clte()

        assert result.vulnerable is False
        assert result.technique == "CL.TE"

    def test_clte_detects_timing_desync_without_status_anomaly(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # No 4xx/5xx anomaly — a real CL.TE often shows ONLY a timing delay
        # (back-end waiting for a chunk terminator). Simulate elapsed time
        # deterministically by advancing a fake clock across _timed_send.
        patch_raw_sender(monkeypatch, lambda _raw: http_response())
        clock = iter([0.0, 9.5, 9.5, 9.5])
        monkeypatch.setattr(smuggling.time, "monotonic", lambda: next(clock))

        result = SmugglingDetector("http://target.test/").test_clte()

        assert result.vulnerable is True
        assert result.technique == "CL.TE"
        assert result.timing_diff >= 8.0
        assert "delayed" in result.evidence

    def test_tecl_detects_probe_anomaly(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def responder(raw: bytes) -> bytes:
            if b"8\r\nSMUGGLED" in raw:
                return http_response()
            return http_response(500, "Internal Server Error", "backend parsed smuggled prefix")

        patch_raw_sender(monkeypatch, responder)

        result = SmugglingDetector("http://target.test/").test_tecl()

        assert result.vulnerable is True
        assert result.technique == "TE.CL"
        assert "response anomaly" in result.evidence

    def test_tecl_reports_clean_for_consistent_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        patch_raw_sender(monkeypatch, lambda _raw: http_response())

        result = SmugglingDetector("http://target.test/").test_tecl()

        assert result.vulnerable is False
        assert result.technique == "TE.CL"

    def test_tete_detects_obfuscated_transfer_encoding(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def responder(raw: bytes) -> bytes:
            if raw.startswith(b"GET / HTTP/1.1"):
                return http_response(400, "Bad Request", "smuggled prefix")
            return http_response()

        patch_raw_sender(monkeypatch, responder)

        result = SmugglingDetector("http://target.test/").test_tete()

        assert result.vulnerable is True
        assert result.technique == "TE.TE"
        assert result.details["obfuscation"] == "Transfer-Encoding: chunked"

    def test_tete_reports_clean_for_consistent_responses(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        patch_raw_sender(monkeypatch, lambda _raw: http_response())

        result = SmugglingDetector("http://target.test/").test_tete()

        assert result.vulnerable is False
        assert result.technique == "TE.TE"


class TestSmugglingExploits:
    def test_exploit_clte_surfaces_smuggled_response(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        patch_raw_sender(monkeypatch, lambda _raw: http_response(body="admin=true"))

        result = SmugglingDetector("http://target.test/").exploit_clte(
            "/admin",
            smuggled_body="role=admin",
        )

        assert result["success"] is True
        assert result["status"] == 200
        assert result["response"] == "admin=true"

    def test_exploit_clte_returns_nothing_for_benign_response(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        patch_raw_sender(monkeypatch, lambda _raw: http_response())

        result = SmugglingDetector("http://target.test/").exploit_clte("/admin")

        assert result["success"] is False
        assert result["status"] == 200
        assert result["response"] == ""

    def test_exploit_store_response_surfaces_poisoned_content(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def responder(raw: bytes) -> bytes:
            if raw.startswith(b"GET /victim HTTP/1.1"):
                return http_response(body="cached secret")
            return http_response()

        patch_raw_sender(monkeypatch, responder)

        result = SmugglingDetector("http://target.test/").exploit_store_response(
            "/secret",
            victim_path="/victim",
        )

        assert result["success"] is True
        assert result["status"] == 200
        assert result["response"] == "cached secret"

    def test_exploit_store_response_returns_nothing_for_benign_response(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        patch_raw_sender(monkeypatch, lambda _raw: http_response())

        result = SmugglingDetector("http://target.test/").exploit_store_response("/secret")

        assert result["success"] is False
        assert result["status"] == 200
        assert result["response"] == ""
