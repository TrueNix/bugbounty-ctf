"""Tests for SessionRecorder request capture and replay."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bugbounty_ctf.session_recorder import SessionRecorder


class _FakeResponse:
    def __init__(self, status: int = 200, text: str = "ok") -> None:
        self.status_code = status
        self.text = text
        self.headers: dict[str, str] = {}


class _FakeScanner:
    """Minimal scanner exposing a recordable _make_request."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def _make_request(self, method: str, url: str, **kwargs: Any) -> _FakeResponse:
        self.calls.append((method, url, kwargs))
        return _FakeResponse()


class TestRecording:
    def test_get_params_recorded_in_params_not_headers(self) -> None:
        sc = _FakeScanner()
        rec = SessionRecorder()
        rec.attach(sc)
        sc._make_request("GET", "http://t/x", params={"id": "1"})
        assert rec.records[0].params == {"id": "1"}
        assert rec.records[0].headers == {}

    def test_headers_and_body_recorded(self) -> None:
        sc = _FakeScanner()
        rec = SessionRecorder()
        rec.attach(sc)
        sc._make_request("POST", "http://t/login", data={"u": "a"}, headers={"X-Test": "1"})
        record = rec.records[0]
        assert record.headers == {"X-Test": "1"}
        assert '"u": "a"' in record.body

    def test_detach_stops_recording(self) -> None:
        sc = _FakeScanner()
        rec = SessionRecorder()
        rec.attach(sc)
        sc._make_request("GET", "http://t/a")
        assert len(rec.records) == 1
        rec.detach()
        sc._make_request("GET", "http://t/b")
        # After detach the call no longer flows through the recorder.
        assert len(rec.records) == 1


class TestReplay:
    def test_replay_resends_get_params(self, tmp_path: Path) -> None:
        sc = _FakeScanner()
        rec = SessionRecorder()
        rec.attach(sc)
        sc._make_request("GET", "http://t/x", params={"id": "1"})

        path = tmp_path / "session.json"
        rec.export(str(path))

        sc2 = _FakeScanner()
        rec2 = SessionRecorder()
        rec2.attach(sc2)
        rec2.replay(str(path))

        # The replayed request must carry the original query params, not hit
        # the bare URL.
        assert any(call[2].get("params") == {"id": "1"} for call in sc2.calls)

    def test_replay_resends_post_body(self, tmp_path: Path) -> None:
        sc = _FakeScanner()
        rec = SessionRecorder()
        rec.attach(sc)
        sc._make_request("POST", "http://t/login", data={"u": "a", "p": "b"})

        path = tmp_path / "session.json"
        rec.export(str(path))

        sc2 = _FakeScanner()
        rec2 = SessionRecorder()
        rec2.attach(sc2)
        rec2.replay(str(path))

        assert any(call[2].get("data") == {"u": "a", "p": "b"} for call in sc2.calls)

    def test_replay_without_scanner_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.json"
        path.write_text("[]")
        rec = SessionRecorder()
        assert rec.replay(str(path)) == []


class TestSummary:
    def test_summary_counts_requests(self) -> None:
        sc = _FakeScanner()
        rec = SessionRecorder()
        rec.attach(sc)
        sc._make_request("GET", "http://t/a")
        sc._make_request("GET", "http://t/b")
        summary = rec.summary()
        assert summary["total_requests"] == 2
        assert summary["unique_urls"] == 2
