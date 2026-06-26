"""Failure taxonomy for HTTP request errors.

Replaces the catch-all status_code=0 with a structured failure
taxonomy that distinguishes timeout, connection refused, DNS, SSL,
and HTTP errors. Each failure type has a different retry strategy.

Usage:
    from bugbounty_ctf.failures import FailureType, RequestFailure, handle_failure

    try:
        response = scanner._make_request("GET", url)
        if response.status_code == 0:
            failure = RequestFailure.from_response(response)
            print(f"Failure: {failure.type} — {failure.message}")
            action = handle_failure(failure)
    except requests.exceptions.RequestException as e:
        failure = RequestFailure.from_exception(e)
        action = handle_failure(failure)
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import requests


class FailureType(Enum):
    """Taxonomy of HTTP request failure types."""

    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    CONNECTION_RESET = "connection_reset"
    DNS_RESOLUTION = "dns_resolution"
    SSL_ERROR = "ssl_error"
    HTTP_4XX = "http_4xx"
    HTTP_5XX = "http_5xx"
    RATE_LIMITED = "rate_limited"
    UNKNOWN = "unknown"

    @property
    def retryable(self) -> bool:
        """Whether this failure type is worth retrying."""
        return self in (
            FailureType.TIMEOUT,
            FailureType.CONNECTION_RESET,
            FailureType.HTTP_5XX,
            FailureType.RATE_LIMITED,
        )

    @property
    def retry_delay(self) -> float:
        """Delay before retry for this failure type."""
        delays = {
            FailureType.TIMEOUT: 2.0,
            FailureType.CONNECTION_RESET: 1.0,
            FailureType.HTTP_5XX: 1.0,
            FailureType.RATE_LIMITED: 5.0,
        }
        return delays.get(self, 0.0)

    @property
    def max_retries(self) -> int:
        """Maximum retries for this failure type."""
        return 3 if self.retryable else 0


@dataclass
class RequestFailure:
    """A structured request failure with type, message, and retry info."""

    type: FailureType
    message: str
    url: str = ""
    status_code: int = 0
    retryable: bool = True
    retry_delay: float = 0.0
    max_retries: int = 0

    def __post_init__(self) -> None:
        self.retryable = self.type.retryable
        self.retry_delay = self.type.retry_delay
        self.max_retries = self.type.max_retries

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "message": self.message[:200],
            "url": self.url,
            "status_code": self.status_code,
            "retryable": self.retryable,
            "retry_delay": self.retry_delay,
            "max_retries": self.max_retries,
        }

    @classmethod
    def from_exception(cls, exc: Exception, url: str = "") -> RequestFailure:
        """Classify a requests exception into a failure type."""
        if isinstance(exc, requests.exceptions.Timeout):
            return cls(FailureType.TIMEOUT, f"Timeout: {exc}", url=url)
        if isinstance(exc, requests.exceptions.ConnectionError):
            msg = str(exc).lower()
            if "refused" in msg:
                return cls(FailureType.CONNECTION_REFUSED, f"Connection refused: {exc}", url=url)
            if "reset" in msg:
                return cls(FailureType.CONNECTION_RESET, f"Connection reset: {exc}", url=url)
            if "name or service not known" in msg or "gaierror" in msg:
                return cls(FailureType.DNS_RESOLUTION, f"DNS error: {exc}", url=url)
            if "ssl" in msg:
                return cls(FailureType.SSL_ERROR, f"SSL error: {exc}", url=url)
            return cls(FailureType.CONNECTION_REFUSED, f"Connection error: {exc}", url=url)
        if isinstance(exc, requests.exceptions.SSLError):
            return cls(FailureType.SSL_ERROR, f"SSL error: {exc}", url=url)
        if isinstance(exc, requests.exceptions.HTTPError):
            return cls(FailureType.HTTP_4XX, f"HTTP error: {exc}", url=url)
        return cls(FailureType.UNKNOWN, f"Unknown error: {exc}", url=url)

    @classmethod
    def from_response(cls, response: requests.Response, url: str = "") -> RequestFailure:
        """Classify a response object (status_code=0 or error response)."""
        text = response.text or ""

        if response.status_code == 0:
            if "timeout" in text.lower():
                return cls(FailureType.TIMEOUT, text[:200], url=url, status_code=0)
            if "refused" in text.lower():
                return cls(FailureType.CONNECTION_REFUSED, text[:200], url=url, status_code=0)
            return cls(FailureType.UNKNOWN, text[:200], url=url, status_code=0)

        if response.status_code == 429:
            return cls(
                FailureType.RATE_LIMITED,
                "Rate limited (429)",
                url=url,
                status_code=429,
            )

        if 400 <= response.status_code < 500:
            return cls(
                FailureType.HTTP_4XX,
                f"HTTP {response.status_code}",
                url=url,
                status_code=response.status_code,
            )

        if response.status_code >= 500:
            return cls(
                FailureType.HTTP_5XX,
                f"HTTP {response.status_code}",
                url=url,
                status_code=response.status_code,
            )

        return cls(FailureType.UNKNOWN, f"Status {response.status_code}", url=url)


def handle_failure(failure: RequestFailure, retry_count: int = 0) -> dict[str, Any]:
    """Determine the action to take for a failure.

    Returns a dict with:
    - action: "retry", "skip", "backoff", or "abort"
    - delay: seconds to wait before retry
    - reason: why this action was chosen
    """
    if not failure.retryable:
        return {"action": "skip", "delay": 0.0, "reason": f"{failure.type.value} not retryable"}

    if retry_count >= failure.max_retries:
        return {
            "action": "abort",
            "delay": 0.0,
            "reason": f"Max retries ({failure.max_retries}) exceeded",
        }

    delay = failure.retry_delay * (2**retry_count)

    if failure.type == FailureType.RATE_LIMITED:
        return {
            "action": "backoff",
            "delay": max(delay, 5.0),
            "reason": "Rate limited — exponential backoff",
        }

    return {
        "action": "retry",
        "delay": delay,
        "reason": f"Retrying {failure.type.value} (attempt {retry_count + 1})",
    }


def execute_with_retry(
    fn: Any,
    url: str,
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> tuple[requests.Response | None, RequestFailure | None]:
    """Execute a request function with structured retry handling.

    Args:
        fn: A callable that takes url and returns (response, failure) tuple
        url: URL to request
        max_retries: Maximum retry attempts
        base_delay: Base delay for exponential backoff

    Returns:
        (response, failure) — one will be None on success/failure
    """
    for attempt in range(max_retries + 1):
        try:
            response, failure = fn(url)

            if response is not None and response.status_code != 0:
                if 200 <= response.status_code < 400:
                    return response, None

                failure = RequestFailure.from_response(response, url=url)

            if failure is None and response is not None:
                failure = RequestFailure.from_response(response, url=url)

            if failure is None:
                return response, None

            action = handle_failure(failure, attempt)

            if action["action"] == "skip" or action["action"] == "abort":
                return None, failure

            delay = action["delay"]
            print(f"  [RETRY] {action['reason']} in {delay:.1f}s")
            time.sleep(delay)

        except requests.exceptions.RequestException as e:
            failure = RequestFailure.from_exception(e, url=url)
            action = handle_failure(failure, attempt)

            if action["action"] == "skip" or action["action"] == "abort":
                return None, failure

            delay = action["delay"]
            print(f"  [RETRY] {action['reason']} in {delay:.1f}s")
            time.sleep(delay)

    return None, RequestFailure(FailureType.UNKNOWN, "Max retries exceeded", url=url)
