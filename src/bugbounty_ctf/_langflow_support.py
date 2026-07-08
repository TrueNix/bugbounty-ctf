from __future__ import annotations

import json as jsonlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol, TypeAlias, TypedDict

import requests

from bugbounty_ctf.template_scan import version_matches

JsonScalar: TypeAlias = str | int | float | bool | None
JsonObject: TypeAlias = dict[str, "JsonValue"]
JsonArray: TypeAlias = list["JsonValue"]
JsonValue: TypeAlias = JsonScalar | JsonObject | JsonArray


class LangflowFingerprint(TypedDict):
    product: str
    version: str


class LangflowFinding(TypedDict):
    type: str
    endpoint: str
    severity: str
    evidence: str
    confidence: str


class LangflowBuildExecResult(TypedDict):
    vulnerable: bool
    confidence: str
    evidence: str
    baseline_s: float | None
    injected_s: float | None
    delta_s: float | None


class LangflowCveMatch(TypedDict):
    product: str
    version: str
    cve: str
    severity: str
    affected: str
    name: str


class _LangflowCve(TypedDict):
    cve: str
    severity: str
    affected: str
    name: str


class ResponseLike(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def text(self) -> str: ...

    def json(self) -> JsonValue: ...


class LangflowFetcher(Protocol):
    def __call__(
        self,
        method: str,
        url: str,
        *,
        timeout: float,
        cookies: Mapping[str, str] | None = None,
        json: JsonValue | None = None,
    ) -> ResponseLike: ...


@dataclass(frozen=True, slots=True)
class LangflowProbeConfig:
    timeout_s: float = 10.0
    sleep_s: float = 2.0
    timing_tolerance_s: float = 0.5
    public_flow_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BuildMeasurement:
    duration_s: float | None
    evidence: str


@dataclass(frozen=True, slots=True)
class _StaticResponse:
    status_code: int
    text: str

    def json(self) -> JsonValue:
        raise ValueError(self.text)


@dataclass(frozen=True, slots=True)
class _RequestsResponse:
    response: requests.Response

    @property
    def status_code(self) -> int:
        return int(self.response.status_code)

    @property
    def text(self) -> str:
        return str(self.response.text)

    def json(self) -> JsonValue:
        decoded: JsonValue = jsonlib.loads(self.text)
        return decoded


_BUILD_DURATION_RE: Final[re.Pattern[str]] = re.compile(
    r'"build_duration"\s*:\s*(?P<seconds>\d+(?:\.\d+)?)'
)
_LANGFLOW_CVES: Final[tuple[_LangflowCve, ...]] = (
    {
        "cve": "CVE-2025-3248",
        "severity": "critical",
        "affected": "<1.3.0",
        "name": "Langflow unauthenticated code validation execution",
    },
    {
        "cve": "CVE-2026-7664",
        "severity": "critical",
        "affected": "<=1.8.4",
        "name": "Langflow MCP unauthenticated exposure",
    },
)


def known_cves(version: str) -> list[LangflowCveMatch]:
    return [
        {
            "product": "langflow",
            "version": version,
            "cve": entry["cve"],
            "severity": entry["severity"],
            "affected": entry["affected"],
            "name": entry["name"],
        }
        for entry in _LANGFLOW_CVES
        if version_matches(version, entry["affected"])
    ]


def requests_response(response: requests.Response) -> ResponseLike:
    return _RequestsResponse(response=response)


def request_error_response(exc: requests.RequestException) -> ResponseLike:
    return _StaticResponse(status_code=0, text=str(exc))


def json_object(response: ResponseLike) -> JsonObject | None:
    try:
        body = response.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def flow_data(public_flow: JsonObject) -> JsonObject:
    data = public_flow.get("data")
    return data if isinstance(data, dict) else public_flow


def timing_oracle(sleep_s: float) -> str:
    return f"import time\ntime.sleep({sleep_s})\n"


def inject_timing_oracle(value: JsonValue, payload: str) -> bool:
    match value:
        case dict():
            code = value.get("code")
            if isinstance(code, str):
                value["code"] = payload
                return True
            if isinstance(code, dict) and isinstance(code.get("value"), str):
                code["value"] = payload
                return True
            return any(inject_timing_oracle(child, payload) for child in value.values())
        case list():
            return any(inject_timing_oracle(child, payload) for child in value)
        case str() | int() | float() | bool() | None:
            return False


def build_duration(response: ResponseLike) -> float | None:
    duration = _duration_from_json(_json_value(response))
    if duration is not None:
        return duration
    return _duration_from_text(response.text)


def _json_value(response: ResponseLike) -> JsonValue | None:
    try:
        return response.json()
    except ValueError:
        return None


def _duration_from_json(value: JsonValue | None) -> float | None:
    match value:
        case dict():
            direct = _numeric_seconds(value.get("build_duration"))
            if direct is not None:
                return direct
            for child in value.values():
                found = _duration_from_json(child)
                if found is not None:
                    return found
            return None
        case list():
            for child in value:
                found = _duration_from_json(child)
                if found is not None:
                    return found
            return None
        case str() | int() | float() | bool() | None:
            return None


def _duration_from_text(text: str) -> float | None:
    for line in text.splitlines():
        payload = line.removeprefix("data:").strip()
        if not payload:
            continue
        try:
            decoded: JsonValue = jsonlib.loads(payload)
        except jsonlib.JSONDecodeError:
            continue
        duration = _duration_from_json(decoded)
        if duration is not None:
            return duration
    match = _BUILD_DURATION_RE.search(text)
    if match is None:
        return None
    return float(match.group("seconds"))


def _numeric_seconds(value: JsonValue | None) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None
