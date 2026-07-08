from __future__ import annotations

import copy
import json as jsonlib
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from bugbounty_ctf.langflow import LangflowProbe, LangflowProbeConfig, known_cves

_FLOW_ID = "public-flow-1"
_PUBLIC_FLOW: dict[str, Any] = {
    "id": _FLOW_ID,
    "data": {
        "nodes": [
            {
                "id": "code-node",
                "data": {
                    "node": {
                        "template": {
                            "code": {
                                "value": "def run() -> str:\n    return 'baseline'\n",
                            },
                        },
                    },
                },
            },
        ],
        "edges": [],
    },
}


@dataclass(frozen=True, slots=True)
class _Call:
    method: str
    path: str
    cookies: dict[str, str]
    json_body: Any | None


class _FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        *,
        json_body: Any | None = None,
        text: str | None = None,
    ) -> None:
        self.status_code = status_code
        self._json_body = json_body
        self.text = text if text is not None else jsonlib.dumps(json_body)
        self.headers: dict[str, str] = {}

    def json(self) -> Any:
        if self._json_body is None:
            raise ValueError("response has no JSON body")
        return self._json_body


class _FakeLangflow:
    def __init__(
        self,
        *,
        baseline_s: float = 0.2,
        injected_s: float = 2.4,
        build_status: int = 200,
        public_flow_status: int = 200,
    ) -> None:
        self.flow_id = _FLOW_ID
        self.baseline_s = baseline_s
        self.injected_s = injected_s
        self.build_status = build_status
        self.public_flow_status = public_flow_status
        self.calls: list[_Call] = []
        self.jobs: dict[str, float] = {}

    def __call__(
        self,
        method: str,
        url: str,
        *,
        timeout: float,
        cookies: dict[str, str] | None = None,
        json: Any | None = None,
    ) -> _FakeResponse:
        path = urlparse(url).path
        self.calls.append(
            _Call(method=method, path=path, cookies=dict(cookies or {}), json_body=json)
        )

        if method == "GET" and path == "/api/v1/version":
            return _FakeResponse(json_body={"version": "1.8.2", "package": "Langflow"})
        if method == "GET" and path == "/openapi.json":
            return _FakeResponse(json_body={"openapi": "3.1.0", "info": {"title": "Langflow"}})
        if method == "GET" and path == "/docs":
            return _FakeResponse(text="<html><title>Swagger UI - Langflow</title></html>")
        if method == "GET" and path == "/api/v1/files/profile_pictures/list":
            return _FakeResponse(json_body={"files": ["avatar.png"]})
        if method == "GET" and path == f"/api/v1/flows/public_flow/{self.flow_id}":
            if self.public_flow_status != 200:
                return _FakeResponse(self.public_flow_status, json_body={"detail": "forbidden"})
            return _FakeResponse(json_body=copy.deepcopy(_PUBLIC_FLOW))
        if method == "POST" and path == f"/api/v1/build_public_tmp/{self.flow_id}/flow":
            if self.build_status != 200:
                return _FakeResponse(self.build_status, json_body={"detail": "auth required"})
            job_id = "injected" if "time.sleep" in jsonlib.dumps(json) else "baseline"
            self.jobs[job_id] = self.injected_s if job_id == "injected" else self.baseline_s
            return _FakeResponse(json_body={"job_id": job_id})
        if (
            method == "GET"
            and path.startswith("/api/v1/build_public_tmp/")
            and path.endswith("/events")
        ):
            job_id = path.split("/")[-2]
            duration_s = self.jobs[job_id]
            return _FakeResponse(text=f'data: {{"build_duration": {duration_s}}}\n\n')
        return _FakeResponse(404, json_body={"detail": "not found"})


def _probe(server: _FakeLangflow) -> LangflowProbe:
    config = LangflowProbeConfig(public_flow_ids=(server.flow_id,))
    return LangflowProbe("http://langflow.test/", config=config, fetcher=server)


def test_fingerprint_parses_version() -> None:
    from bugbounty_ctf.api import LangflowProbe as ApiLangflowProbe

    server = _FakeLangflow()
    fingerprint = _probe(server).fingerprint()

    assert ApiLangflowProbe is LangflowProbe
    assert fingerprint == {"product": "Langflow", "version": "1.8.2"}


def test_unauth_exposure_flags_open_openapi_and_docs() -> None:
    server = _FakeLangflow()
    findings = _probe(server).check_unauth_exposure()
    by_endpoint = {finding["endpoint"]: finding for finding in findings}

    assert by_endpoint["/openapi.json"]["severity"] == "medium"
    assert by_endpoint["/openapi.json"]["confidence"] == "high"
    assert by_endpoint["/docs"]["type"] == "langflow-info-disclosure"
    assert "/api/v1/files/profile_pictures/list" in by_endpoint


def test_public_flow_read_detected() -> None:
    server = _FakeLangflow()
    findings = _probe(server).check_unauth_exposure()

    assert any(
        finding["type"] == "langflow-public-flow-read"
        and finding["endpoint"] == f"/api/v1/flows/public_flow/{server.flow_id}"
        and finding["severity"] == "medium"
        for finding in findings
    )


def test_public_build_exec_timing_oracle_positive() -> None:
    server = _FakeLangflow(baseline_s=0.2, injected_s=2.4)
    result = _probe(server).check_public_build_exec()

    assert result["vulnerable"] is True
    assert result["confidence"] == "high"
    assert result["baseline_s"] == 0.2
    assert result["injected_s"] == 2.4
    assert result["delta_s"] == 2.2
    assert any(
        call.path == f"/api/v1/build_public_tmp/{server.flow_id}/flow"
        and "import time" in jsonlib.dumps(call.json_body)
        and "time.sleep" in jsonlib.dumps(call.json_body)
        for call in server.calls
    )
    assert not any("subprocess" in jsonlib.dumps(call.json_body) for call in server.calls)


def test_public_build_exec_negative() -> None:
    server = _FakeLangflow(baseline_s=0.2, injected_s=0.4, build_status=403)
    result = _probe(server).check_public_build_exec()

    assert result["vulnerable"] is False
    assert result["confidence"] == "unconfirmed"
    assert result["baseline_s"] is None
    assert result["injected_s"] is None
    assert "HTTP 403" in result["evidence"]


def test_client_id_cookie_is_self_issued() -> None:
    server = _FakeLangflow()
    _probe(server).check_public_build_exec()
    build_calls = [
        call
        for call in server.calls
        if call.path == f"/api/v1/build_public_tmp/{server.flow_id}/flow"
    ]

    client_ids = {call.cookies["client_id"] for call in build_calls}
    assert len(client_ids) == 1
    assert uuid.UUID(next(iter(client_ids)))


def test_known_cves_maps_version() -> None:
    cves = known_cves("1.8.2")
    cve_ids = {entry["cve"] for entry in cves}

    assert "CVE-2026-7664" in cve_ids
    assert "CVE-2025-3248" not in cve_ids
    assert all(entry["product"] == "langflow" and entry["version"] == "1.8.2" for entry in cves)
