"""Test fixtures shared across the test suite."""

from __future__ import annotations

import pytest


@pytest.fixture
def fake_baseline_response() -> object:
    """A fake requests.Response for baseline comparisons."""

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200
            self.text = "<html><body>Welcome</body></html>"
            self.headers: dict[str, str] = {"Server": "nginx"}
            self.response_time = 0.1

    return FakeResponse()


@pytest.fixture
def fake_sqli_error_response() -> object:
    """A fake response with SQL error — should trigger 'sql_error' indicator."""

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 500
            self.text = "You have an error in your SQL syntax near 'OR 1=1'"
            self.headers: dict[str, str] = {}
            self.response_time = 0.05

    return FakeResponse()


@pytest.fixture
def fake_command_output_response() -> object:
    """A fake response with command output — should trigger 'command_output'."""

    class FakeResponse:
        def __init__(self) -> None:
            self.status_code = 200
            self.text = "uid=1000(root) gid=1000(root) groups=1000(root)"
            self.headers: dict[str, str] = {}
            self.response_time = 0.05

    return FakeResponse()
