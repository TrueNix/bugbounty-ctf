"""Tests for JWT functions — decode, forge alg=none, forge HS256."""

from __future__ import annotations

import base64
import json

from bugbounty_ctf.advanced_tests import decode_jwt, forge_jwt_alg_none, forge_jwt_hs256


def _make_token(payload: dict, secret: str = "secret") -> str:
    """Helper: create a valid HS256 token."""
    header = {"alg": "HS256", "typ": "JWT"}
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    import hashlib
    import hmac

    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{h}.{p}.{s}"


class TestDecodeJwt:
    def test_decode_valid_token(self) -> None:
        token = _make_token({"user": "admin", "role": "user"})
        decoded = decode_jwt(token)
        assert decoded is not None
        assert decoded["header"]["alg"] == "HS256"
        assert decoded["payload"]["user"] == "admin"

    def test_decode_invalid_token_returns_none(self) -> None:
        # Two parts = wrong number of parts
        assert decode_jwt("only.two") is None
        # Three parts but invalid base64 returns error dict
        result = decode_jwt("!!!.!!!.!!!")
        assert result is not None
        assert "error" in result


class TestForgeAlgNone:
    def test_forge_alg_none_creates_valid_structure(self) -> None:
        token = forge_jwt_alg_none({"role": "admin"})
        parts = token.split(".")
        assert len(parts) == 3
        # Last part should be empty (no signature)
        assert parts[2] == ""

    def test_forge_alg_none_header(self) -> None:
        token = forge_jwt_alg_none({"role": "admin"})
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["alg"] == "none"

    def test_forge_alg_none_payload(self) -> None:
        token = forge_jwt_alg_none({"role": "admin", "user": "test"})
        parts = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        assert payload["role"] == "admin"
        assert payload["user"] == "test"


class TestForgeHS256:
    def test_forge_hs256_creates_valid_structure(self) -> None:
        token = forge_jwt_hs256({"role": "admin"}, "secret")
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] != ""  # Has signature

    def test_forge_hs256_header(self) -> None:
        token = forge_jwt_hs256({"role": "admin"}, "secret")
        parts = token.split(".")
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        assert header["alg"] == "HS256"

    def test_forge_hs256_with_string_secret(self) -> None:
        token = forge_jwt_hs256({"x": 1}, "mysecret")
        # Verify we can decode the header/payload
        parts = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        assert payload["x"] == 1

    def test_forge_hs256_with_bytes_secret(self) -> None:
        token = forge_jwt_hs256({"x": 1}, b"mysecret")
        parts = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        assert payload["x"] == 1

    def test_forge_hs256_empty_secret(self) -> None:
        token = forge_jwt_hs256({"role": "admin"}, "")
        parts = token.split(".")
        assert len(parts) == 3
        # The signature with empty secret should be deterministic
        assert parts[2] != ""
