"""Session recording and replay — record all requests/responses for debugging.

Wraps the scanner's _make_request to capture every HTTP interaction
into a structured log that can be replayed, inspected, or exported.

Usage:
    from bugbounty_ctf.session_recorder import SessionRecorder

    recorder = SessionRecorder()
    recorder.attach(scanner)
    # ... run tests ...
    recorder.export("session.json")
    # Or replay:
    recorder.replay("session.json")
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class RecordedRequest:
    """A single recorded HTTP request/response pair."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    status_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_time: float = 0.0
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body[:1000],
            "timestamp": self.timestamp,
            "status_code": self.status_code,
            "response_headers": dict(self.response_headers),
            "response_body": self.response_body[:2000],
            "response_time": self.response_time,
            "error": self.error[:200],
        }


class SessionRecorder:
    """Records all HTTP requests/responses for debugging and replay.

    Attach to a SecurityScanner to automatically record every request.
    Export to JSON for offline analysis or replay.
    """

    def __init__(self) -> None:
        self.records: list[RecordedRequest] = []
        self._original_make_request: Any = None
        self._scanner: Any = None

    def attach(self, scanner: Any) -> None:
        """Attach to a SecurityScanner to record all requests."""
        self._scanner = scanner
        self._original_make_request = scanner._make_request

        def recorded_make_request(method: str, url: str, **kwargs: Any) -> Any:
            record = RecordedRequest(method=method, url=url)

            data = kwargs.get("data")
            params = kwargs.get("params")
            if data:
                if isinstance(data, dict):
                    record.body = json.dumps(data)
                else:
                    record.body = str(data)
            if params and isinstance(params, dict):
                record.headers = dict(params)

            start = time.time()
            response = self._original_make_request(method, url, **kwargs)
            elapsed = time.time() - start

            record.status_code = response.status_code
            record.response_headers = dict(response.headers)
            record.response_body = response.text[:2000]
            record.response_time = elapsed

            self.records.append(record)
            return response

        scanner._make_request = recorded_make_request

    def detach(self) -> None:
        """Restore the original _make_request."""
        if self._scanner and self._original_make_request:
            self._scanner._make_request = self._original_make_request
            self._scanner = None

    def export(self, path: str) -> str:
        """Export session to JSON file."""
        with open(path, "w") as f:
            json.dump([r.to_dict() for r in self.records], f, indent=2)
        print(f"[*] Session exported: {len(self.records)} requests → {path}")
        return path

    def replay(self, path: str) -> list[dict[str, Any]]:
        """Replay a recorded session from JSON.

        Returns a list of dicts comparing original vs replayed responses.
        """
        with open(path) as f:
            records = json.load(f)

        if not self._scanner:
            print("[-] No scanner attached for replay")
            return []

        results: list[dict[str, Any]] = []
        for record in records[:50]:
            method = record["method"]
            url = record["url"]
            response = self._scanner._make_request(method, url)

            match = response.status_code == record["status_code"]
            results.append(
                {
                    "url": url,
                    "method": method,
                    "original_status": record["status_code"],
                    "replayed_status": response.status_code,
                    "match": match,
                    "original_length": len(record.get("response_body", "")),
                    "replayed_length": len(response.text),
                }
            )
            marker = "[+]" if match else "[!]"
            print(f"  {marker} {method} {url}: {record['status_code']}→{response.status_code}")

        return results

    def summary(self) -> dict[str, Any]:
        """Return a summary of the recorded session."""
        status_codes: dict[int, int] = {}
        total_time = 0.0
        errors = 0

        for r in self.records:
            status_codes[r.status_code] = status_codes.get(r.status_code, 0) + 1
            total_time += r.response_time
            if r.error:
                errors += 1

        return {
            "total_requests": len(self.records),
            "status_codes": status_codes,
            "total_time": round(total_time, 2),
            "avg_response_time": round(total_time / max(len(self.records), 1), 3),
            "errors": errors,
            "unique_urls": len({r.url for r in self.records}),
        }

    def find_interesting(self) -> list[RecordedRequest]:
        """Find requests with interesting responses (errors, flags, large diffs)."""
        interesting: list[RecordedRequest] = []

        for r in self.records:
            if (
                r.status_code >= 500
                or (r.status_code == 0 and r.error)
                or "HTB{" in r.response_body
                or "flag{" in r.response_body
                or ("error" in r.response_body.lower()[:200] and r.status_code != 200)
            ):
                interesting.append(r)

        return interesting

    def get_records(self) -> list[dict[str, Any]]:
        """Return all records as dicts."""
        return [r.to_dict() for r in self.records]
