"""Tests for race condition testing."""

from __future__ import annotations

import pytest
import responses

from bugbounty_ctf.advanced_tests import test_race_condition as run_race_condition


class TestRaceCondition:
    @responses.activate
    def test_race_condition_detected_on_multiple_successes(self) -> None:
        for _ in range(30):
            responses.add(
                responses.POST,
                "http://target/redeem",
                json={"success": True},
                status=200,
            )

        result = run_race_condition(
            "http://target/redeem",
            data={"code": "X"},
            workers=5,
            total_requests=10,
        )

        assert result["raced"] is True
        assert result["success_count"] == 10
        assert result["total_requests"] == 10

    @responses.activate
    def test_no_race_when_single_success(self) -> None:
        responses.add(responses.POST, "http://target/redeem", json={"ok": True}, status=200)
        for _ in range(29):
            responses.add(
                responses.POST,
                "http://target/redeem",
                json={"error": "already redeemed"},
                status=409,
            )

        result = run_race_condition(
            "http://target/redeem",
            data={"code": "X"},
            workers=5,
            total_requests=30,
        )

        assert result["raced"] is False
        assert result["success_count"] == 1

    def test_raises_on_no_data(self) -> None:
        with pytest.raises(ValueError, match="Provide either"):
            run_race_condition("http://target/redeem")
