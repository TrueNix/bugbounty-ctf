from __future__ import annotations

from bugbounty_ctf.websocket import WebSocketTester


class StaticResponseWebSocketTester(WebSocketTester):
    def __init__(self, response: str) -> None:
        super().__init__("ws://example.test/socket")
        self._response = response

    def send_message(self, message: str) -> str:
        return self._response


def test_injection_does_not_report_ssti_when_response_contains_incidental_number() -> None:
    # Given: a response that contains 49 only as part of unrelated business text.
    tester = StaticResponseWebSocketTester("order number 1490 accepted")

    # When: the historical Jinja arithmetic probe is sent.
    result = tester.test_injection("{{7*7}}")

    # Then: the incidental number is not treated as evaluated SSTI output.
    assert result.interesting is False
    assert result.details.get("indicator") != "ssti_evaluated"


def test_injection_reports_ssti_when_response_contains_exact_evaluated_token() -> None:
    # Given: a response containing the evaluated arithmetic result as a standalone token.
    tester = StaticResponseWebSocketTester("render result 49 accepted")

    # When: the matching Jinja arithmetic probe is sent.
    result = tester.test_injection("{{7*7}}")

    # Then: the response is reported as evaluated SSTI output.
    assert result.interesting is True
    assert result.details["indicator"] == "ssti_evaluated"


def test_injection_does_not_report_ssti_when_payload_is_reflected() -> None:
    # Given: a response that reflects the payload alongside an incidental result-like token.
    tester = StaticResponseWebSocketTester("debug echoed {{7*7}} then mentioned 49")

    # When: the reflected Jinja arithmetic probe is sent.
    result = tester.test_injection("{{7*7}}")

    # Then: reflection is not treated as evaluated SSTI output.
    assert result.interesting is False
    assert result.details.get("indicator") != "ssti_evaluated"
