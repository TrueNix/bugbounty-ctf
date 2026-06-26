"""Tests for the crypto toolkit."""

from __future__ import annotations

from bugbounty_ctf.crypto import CryptoToolkit


class TestDecodeChain:
    def test_base64_decode(self) -> None:
        ct = CryptoToolkit()
        result = ct.decode_chain("dGVzdCBmbGFnIHtmbGFnX3Rlc3R9")
        assert result.success
        assert "test flag {flag_test}" in result.result

    def test_hex_decode(self) -> None:
        ct = CryptoToolkit()
        result = ct.decode_chain("666c61677b6865785f6465636f6465647d")
        assert result.success
        assert "flag{hex_decoded}" in result.result

    def test_multi_layer_decode(self) -> None:
        ct = CryptoToolkit()
        import base64

        encoded = base64.b64encode(b"flag{multi_layer}").decode()
        result = ct.decode_chain(encoded)
        assert "flag{multi_layer}" in result.result

    def test_no_decode_possible(self) -> None:
        ct = CryptoToolkit()
        result = ct.decode_chain("plaintext")
        assert not result.success


class TestRSASmallExponent:
    def test_cube_root(self) -> None:
        ct = CryptoToolkit()
        m = 12345
        e = 3
        n = m**e + 1000
        c = m**e
        result = ct.rsa_small_exponent(n=n, e=e, c=c)
        assert result.success
        assert result.details.get("root") == 12345


class TestXORBruteforce:
    def test_single_byte_xor(self) -> None:
        ct = CryptoToolkit()
        plaintext = b"flag{xor_cracked}"
        key = 42
        ciphertext = bytes(c ^ key for c in plaintext)
        result = ct.xor_bruteforce(ciphertext)
        assert result.success
        assert "flag{xor_cracked}" in result.result

    def test_no_flag_in_output(self) -> None:
        ct = CryptoToolkit()
        ciphertext = bytes(range(20))
        result = ct.xor_bruteforce(ciphertext)
        assert isinstance(result.success, bool)


class TestHashCrack:
    def test_crack_md5(self) -> None:
        import hashlib

        ct = CryptoToolkit()
        h = hashlib.md5(b"password").hexdigest()
        result = ct.hash_crack(h, hash_type="md5")
        assert result.success
        assert result.result == "password"

    def test_crack_sha256(self) -> None:
        import hashlib

        ct = CryptoToolkit()
        h = hashlib.sha256(b"admin").hexdigest()
        result = ct.hash_crack(h, hash_type="sha256")
        assert result.success
        assert result.result == "admin"

    def test_auto_detect_hash_type(self) -> None:
        import hashlib

        ct = CryptoToolkit()
        h = hashlib.md5(b"root").hexdigest()
        result = ct.hash_crack(h)
        assert result.success
        assert result.result == "root"

    def test_failed_crack(self) -> None:
        ct = CryptoToolkit()
        result = ct.hash_crack("ffffffffffffffffffffffffffffffff", hash_type="md5")
        assert not result.success


class TestHashIdentify:
    def test_identify_md5(self) -> None:
        ct = CryptoToolkit()
        info = ct.hash_identify("d41d8cd98f00b204e9800998ecf8427e")
        assert info["length"] == 32
        assert "md5" in info["possible_types"]
        assert info["is_hex"]

    def test_identify_sha256(self) -> None:
        ct = CryptoToolkit()
        info = ct.hash_identify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert info["length"] == 64
        assert "sha256" in info["possible_types"]
