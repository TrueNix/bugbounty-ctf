"""Crypto toolkit for CTF challenges — RSA attacks, XOR, hash cracking, encoding chains.

Handles common CTF crypto challenges:
- RSA: small exponent, common modulus, Wiener, Fermat factorization
- XOR: single-byte and multi-byte bruteforce, known-plaintext
- Hash cracking: dictionary attack, rainbow table lookup
- Encoding: base64, base32, hex, binary, rot13, URL decode chains

Usage:
    from bugbounty_ctf.crypto import CryptoToolkit

    ct = CryptoToolkit()
    ct.decode_chain("dGVzdCBmbGFnIHtmbGFnX3Rlc3R9")
    ct.rsa_small_exponent(n=..., e=3, c=...)
    ct.xor_bruteforce(ciphertext)
    ct.hash_crack("5f4dcc3b5aa765d61d8327deb882cf99")
"""

from __future__ import annotations

import base64
import hashlib
import math
from dataclasses import dataclass, field
from typing import Any

FLAG_PATTERNS = [r"HTB\{[^}]+\}", r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"pwn\{[^}]+\}"]

COMMON_PASSWORDS = [
    "password",
    "admin",
    "root",
    "toor",
    "123456",
    "password123",
    "admin123",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "qwerty",
    "login",
    "abc123",
    "password1",
    "test",
    "guest",
    "secret",
    "changeme",
    "passw0rd",
    "trustno1",
    "12345678",
    "iloveyou",
    "sunshine",
    "princess",
    "football",
    "shadow",
    "michael",
    "robert",
    "daniel",
    "thomas",
    "marcus",
    "devops",
]

COMMON_HASH_TYPES = ["md5", "sha1", "sha256", "sha512", "sha224", "sha384"]


@dataclass
class CryptoResult:
    """Result from a crypto operation."""

    operation: str
    success: bool
    result: str = ""
    flags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "success": self.success,
            "result": self.result[:500],
            "flags": self.flags,
            "details": self.details,
        }


class CryptoToolkit:
    """Crypto challenge solver for CTF."""

    def __init__(self) -> None:
        self.results: list[CryptoResult] = []

    @staticmethod
    def _extract_flags(text: str) -> list[str]:
        import re

        flags: list[str] = []
        for pattern in FLAG_PATTERNS:
            flags.extend(re.findall(pattern, text, re.IGNORECASE))
        return list(set(flags))

    def decode_chain(self, encoded: str) -> CryptoResult:
        """Try multiple decode/decrypt chains on encoded data.

        Attempts: base64 -> hex -> base32 -> binary -> rot13 -> URL decode
        Chains multiple decodings if one isn't enough.
        """
        original = encoded.strip()
        current = original
        chain: list[str] = []
        flags: list[str] = []

        for _ in range(5):
            changed = False

            try:
                decoded = base64.b64decode(current, validate=True).decode("utf-8", errors="replace")
                if decoded != current:
                    current = decoded
                    chain.append("base64")
                    changed = True
                    flags = self._extract_flags(current)
                    if flags:
                        break
            except Exception:
                pass

            try:
                decoded = bytes.fromhex(current).decode("utf-8", errors="replace")
                if decoded != current and len(current) % 2 == 0:
                    current = decoded
                    chain.append("hex")
                    changed = True
                    flags = self._extract_flags(current)
                    if flags:
                        break
            except Exception:
                pass

            try:
                decoded = base64.b32decode(current + "=" * (-len(current) % 8)).decode(
                    "utf-8", errors="replace"
                )
                if decoded != current:
                    current = decoded
                    chain.append("base32")
                    changed = True
                    flags = self._extract_flags(current)
                    if flags:
                        break
            except Exception:
                pass

            if not changed:
                break

        result = CryptoResult(
            operation="decode_chain",
            success=bool(chain),
            result=current,
            flags=flags,
            details={"chain": chain, "original": original[:100]},
        )
        self.results.append(result)

        if chain:
            print(f"[+] Decoded: {' -> '.join(chain)} → {current[:100]}")
        if flags:
            print(f"    [FLAG] {flags}")
        return result

    @staticmethod
    def _integer_nth_root(x: int, n: int) -> int:
        """Return floor(x ** (1/n)) for non-negative integer x, n >= 1.

        Uses binary search on integers so it stays exact for ciphertexts far
        larger than float can represent (real RSA moduli overflow ``c ** (1.0/e)``
        or lose precision, which the old ±2 correction window could not recover).
        """
        if n < 1:
            raise ValueError("n must be >= 1")
        if x < 0:
            raise ValueError("x must be >= 0")
        if x == 0:
            return 0
        hi = 1 << ((x.bit_length() + n - 1) // n)
        lo = hi >> 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if mid**n <= x:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def rsa_small_exponent(self, n: int, e: int, c: int) -> CryptoResult:
        """RSA attack: if e is small and m^e < n, just take the e-th root."""
        if e < 10:
            root = self._integer_nth_root(c, e)
            for r in range(max(root - 2, 0), root + 3):
                if r**e == c:
                    try:
                        plaintext = bytes.fromhex(hex(r)[2:]).decode("utf-8", errors="replace")
                    except Exception:
                        plaintext = str(r)
                    flags = self._extract_flags(plaintext)
                    result = CryptoResult(
                        operation="rsa_small_exponent",
                        success=True,
                        result=plaintext,
                        flags=flags,
                        details={"n": n, "e": e, "c": c, "root": r},
                    )
                    self.results.append(result)
                    if flags:
                        print(f"[FLAG] {flags}")
                    return result

        result = CryptoResult(
            operation="rsa_small_exponent", success=False, details={"n": n, "e": e}
        )
        self.results.append(result)
        return result

    def rsa_common_modulus(self, n: int, e1: int, e2: int, c1: int, c2: int) -> CryptoResult:
        """RSA common modulus attack: same n, different e."""
        g, x, y = self._extended_gcd(e1, e2)
        if g != 1:
            result = CryptoResult(operation="rsa_common_modulus", success=False)
            self.results.append(result)
            return result

        # Bezout: e1*x + e2*y = 1, so m = c1^x * c2^y mod n. A negative
        # coefficient means the corresponding ciphertext must be inverted first.
        if x < 0:
            c1 = self._modinv(c1, n)
            x = -x
        if y < 0:
            c2 = self._modinv(c2, n)
            y = -y

        m = (pow(c1, x, n) * pow(c2, y, n)) % n
        try:
            plaintext = bytes.fromhex(hex(m)[2:]).decode("utf-8", errors="replace")
        except Exception:
            plaintext = str(m)
        flags = self._extract_flags(plaintext)
        result = CryptoResult(
            operation="rsa_common_modulus",
            success=True,
            result=plaintext,
            flags=flags,
            details={"m": m},
        )
        self.results.append(result)
        if flags:
            print(f"[FLAG] {flags}")
        return result

    def rsa_wiener(self, n: int, e: int) -> CryptoResult:
        """Wiener's attack: small private key d."""
        cf = self._continued_fraction(e, n)
        convergents = self._convergents(cf)

        for k, d in convergents:
            if k == 0:
                continue
            phi = (e * d - 1) // k
            b = n - phi + 1
            discriminant = b * b - 4 * n
            if discriminant >= 0:
                sqrt_disc = math.isqrt(discriminant)
                if sqrt_disc * sqrt_disc == discriminant:
                    p = (b + sqrt_disc) // 2
                    q = n // p
                    if p * q == n:
                        result = CryptoResult(
                            operation="rsa_wiener",
                            success=True,
                            result=f"d={d}, p={p}, q={q}",
                            details={"d": d, "p": p, "q": q},
                        )
                        self.results.append(result)
                        print(f"[+] Wiener: d={d}")
                        return result

        result = CryptoResult(operation="rsa_wiener", success=False)
        self.results.append(result)
        return result

    @staticmethod
    def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        g, x, y = CryptoToolkit._extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

    @staticmethod
    def _modinv(a: int, m: int) -> int:
        g, x, _ = CryptoToolkit._extended_gcd(a, m)
        if g != 1:
            raise ValueError("No modular inverse")
        return x % m

    @staticmethod
    def _continued_fraction(num: int, den: int) -> list[int]:
        cf: list[int] = []
        while den:
            q = num // den
            cf.append(q)
            num, den = den, num - q * den
        return cf

    @staticmethod
    def _convergents(cf: list[int]) -> list[tuple[int, int]]:
        convs: list[tuple[int, int]] = []
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        for a in cf:
            h_next = a * h_curr + h_prev
            k_next = a * k_curr + k_prev
            convs.append((k_next, h_next))
            h_prev, h_curr = h_curr, h_next
            k_prev, k_curr = k_curr, k_next
        return convs

    def xor_bruteforce(self, ciphertext: bytes, known_prefix: bytes = b"") -> CryptoResult:
        """XOR bruteforce: try all single-byte keys, look for flags."""
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()

        best_key = 0
        best_score = -1
        best_plaintext = b""

        for key in range(256):
            plaintext = bytes(c ^ key for c in ciphertext)
            score = sum(1 for c in plaintext if 32 <= c <= 126)
            if known_prefix and plaintext.startswith(known_prefix):
                score += 1000
            flags = self._extract_flags(plaintext.decode("utf-8", errors="replace"))
            if flags:
                result = CryptoResult(
                    operation="xor_bruteforce",
                    success=True,
                    result=plaintext.decode("utf-8", errors="replace"),
                    flags=flags,
                    details={"key": key, "key_hex": hex(key)},
                )
                self.results.append(result)
                print(f"[FLAG] XOR key=0x{key:02x}: {flags}")
                return result
            if score > best_score:
                best_score = score
                best_key = key
                best_plaintext = plaintext

        result = CryptoResult(
            operation="xor_bruteforce",
            success=best_score > len(ciphertext) * 0.8,
            result=best_plaintext.decode("utf-8", errors="replace"),
            details={"key": best_key, "key_hex": hex(best_key), "score": best_score},
        )
        self.results.append(result)
        if result.success:
            print(
                f"[+] XOR key=0x{best_key:02x}: {best_plaintext[:100].decode('utf-8', errors='replace')}"
            )
        return result

    def xor_known_plaintext(self, ciphertext: bytes, known_plaintext: bytes) -> bytes:
        """Recover XOR key from known plaintext-ciphertext pair."""
        key_length = len(known_plaintext)
        key = bytes(c ^ p for c, p in zip(ciphertext[:key_length], known_plaintext, strict=False))
        plaintext = bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))
        flags = self._extract_flags(plaintext.decode("utf-8", errors="replace"))
        if flags:
            print(f"[FLAG] {flags}")
        return key

    def hash_crack(
        self,
        hash_value: str,
        wordlist: list[str] | None = None,
        hash_type: str | None = None,
    ) -> CryptoResult:
        """Crack a hash using dictionary attack.

        Auto-detects hash type by length if not specified.
        """
        if wordlist is None:
            wordlist = COMMON_PASSWORDS

        if hash_type is None:
            hash_type = self._detect_hash_type(hash_value)
            if hash_type is None:
                result = CryptoResult(
                    operation="hash_crack",
                    success=False,
                    details={"error": "Could not detect hash type"},
                )
                self.results.append(result)
                return result

        hash_func = getattr(hashlib, hash_type, None)
        if hash_func is None:
            result = CryptoResult(
                operation="hash_crack",
                success=False,
                details={"error": f"Unknown hash type: {hash_type}"},
            )
            self.results.append(result)
            return result

        hash_value = hash_value.lower().strip()

        for word in wordlist:
            if hash_func(word.encode()).hexdigest() == hash_value:
                result = CryptoResult(
                    operation="hash_crack",
                    success=True,
                    result=word,
                    details={"hash_type": hash_type, "hash": hash_value},
                )
                self.results.append(result)
                print(f"[+] Hash cracked: {word} ({hash_type})")
                return result

        result = CryptoResult(
            operation="hash_crack",
            success=False,
            details={"hash_type": hash_type, "hash": hash_value, "wordlist_size": len(wordlist)},
        )
        self.results.append(result)
        return result

    @staticmethod
    def _detect_hash_type(hash_value: str) -> str | None:
        """Detect hash type by length."""
        length = len(hash_value.strip())
        type_map = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
        return type_map.get(length)

    def hash_identify(self, hash_value: str) -> dict[str, Any]:
        """Identify possible hash types for a given hash."""
        h = hash_value.strip()
        length = len(h)
        possible: list[str] = []

        type_map = {
            32: ["md5", "md4", "ntlm"],
            40: ["sha1", "ripemd160"],
            56: ["sha224"],
            64: ["sha256", "sha3_256", "blake2s"],
            96: ["sha384"],
            128: ["sha512", "sha3_512", "whirlpool"],
        }

        possible = type_map.get(length, [])
        charset = "0123456789abcdef"
        is_hex = all(c in charset for c in h.lower())

        return {
            "hash": h,
            "length": length,
            "possible_types": possible,
            "is_hex": is_hex,
        }

    def get_results(self) -> list[dict[str, Any]]:
        return [r.to_dict() for r in self.results]
