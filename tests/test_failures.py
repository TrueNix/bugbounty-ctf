"""Tests for the failure taxonomy module."""

from __future__ import annotations

import requests

from bugbounty_ctf.failures import FailureType, RequestFailure, handle_failure


class TestFailureType:
    def test_timeout_is_retryable(self) -> None:
        assert FailureType.TIMEOUT.retryable is True

    def test_dns_not_retryable(self) -> None:
        assert FailureType.DNS_RESOLUTION.retryable is False

    def test_rate_limited_has_delay(self) -> None:
        assert FailureType.RATE_LIMITED.retry_delay == 5.0

    def test_connection_refused_not_retryable(self) -> None:
        assert FailureType.CONNECTION_REFUSED.retryable is False


class TestRequestFailure:
    def test_from_timeout_exception(self) -> None:
        exc = requests.exceptions.Timeout("Connection timed out")
        failure = RequestFailure.from_exception(exc, url="http://target/")
        assert failure.type == FailureType.TIMEOUT
        assert failure.url == "http://target/"

    def test_from_connection_error_refused(self) -> None:
        exc = requests.exceptions.ConnectionError("Connection refused")
        failure = RequestFailure.from_exception(exc)
        assert failure.type == FailureType.CONNECTION_REFUSED

    def test_from_connection_error_dns(self) -> None:
        exc = requests.exceptions.ConnectionError("Name or service not known")
        failure = RequestFailure.from_exception(exc)
        assert failure.type == FailureType.DNS_RESOLUTION

    def test_from_response_rate_limited(self) -> None:
        response = requests.Response()
        response.status_code = 429
        response._content = b"Too Many Requests"
        failure = RequestFailure.from_response(response, url="http://target/api")
        assert failure.type == FailureType.RATE_LIMITED
        assert failure.status_code == 429

    def test_from_response_5xx(self) -> None:
        response = requests.Response()
        response.status_code = 503
        response._content = b"Service Unavailable"
        failure = RequestFailure.from_response(response)
        assert failure.type == FailureType.HTTP_5XX

    def test_to_dict(self) -> None:
        failure = RequestFailure(FailureType.TIMEOUT, "timed out", url="http://x/")
        d = failure.to_dict()
        assert d["type"] == "timeout"
        assert d["retryable"] is True


class TestHandleFailure:
    def test_retry_timeout(self) -> None:
        failure = RequestFailure(FailureType.TIMEOUT, "timed out")
        action = handle_failure(failure, retry_count=0)
        assert action["action"] == "retry"
        assert action["delay"] > 0

    def test_skip_dns(self) -> None:
        failure = RequestFailure(FailureType.DNS_RESOLUTION, "dns error")
        action = handle_failure(failure, retry_count=0)
        assert action["action"] == "skip"

    def test_abort_after_max_retries(self) -> None:
        failure = RequestFailure(FailureType.TIMEOUT, "timed out")
        action = handle_failure(failure, retry_count=3)
        assert action["action"] == "abort"

    def test_backoff_for_rate_limit(self) -> None:
        failure = RequestFailure(FailureType.RATE_LIMITED, "429")
        action = handle_failure(failure, retry_count=0)
        assert action["action"] == "backoff"
        assert action["delay"] >= 5.0
