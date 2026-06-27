"""Forensics module — PCAP, steganography, memory, disk image analysis.

Handles common CTF forensics challenges:
- PCAP: extract HTTP, DNS, FTP, credentials from network captures
- Steganography: detect hidden data in images (LSB, binwalk, zsteg)
- Memory: analyze memory dumps for processes, credentials
- Disk: enumerate and extract files from disk images

Usage:
    from bugbounty_ctf.forensics import ForensicsToolkit

    ft = ForensicsToolkit()
    ft.analyze_pcap("capture.pcap")
    ft.analyze_image("suspicious.png")
    ft.analyze_binary("challenge.bin")
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

FLAG_PATTERNS = [r"HTB\{[^}]+\}", r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"pwn\{[^}]+\}"]


@dataclass
class ForensicFinding:
    """A finding from forensic analysis."""

    tool: str
    finding_type: str
    value: str = ""
    is_flag: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "finding_type": self.finding_type,
            "value": self.value[:500],
            "is_flag": self.is_flag,
            "details": self.details,
        }


def _extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for pattern in FLAG_PATTERNS:
        flags.extend(re.findall(pattern, text, re.IGNORECASE))
    return list(set(flags))


def _run_cmd(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command and return stdout, stderr, returncode."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "[TIMEOUT]", -1
    except FileNotFoundError:
        return "", f"[NOT FOUND: {cmd[0]}]", -1


class ForensicsToolkit:
    """Forensic analysis toolkit for CTF challenges."""

    def __init__(self) -> None:
        self.findings: list[ForensicFinding] = []

    def analyze_all(self, file_path: str) -> list[ForensicFinding]:
        """Run all applicable analysis on a file."""
        self.findings = []

        if not os.path.exists(file_path):
            print(f"[-] File not found: {file_path}")
            return []

        self._file_type(file_path)
        self._strings(file_path)
        self._binwalk(file_path)
        self._exiftool(file_path)

        ext = os.path.splitext(file_path)[1].lower()
        if ext in (".pcap", ".pcapng", ".cap"):
            self.analyze_pcap(file_path)
        elif ext in (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff"):
            self.analyze_image(file_path)
        elif ext in (".raw", ".mem", ".vmem", ".dmp"):
            self.analyze_memory(file_path)
        elif ext in (".img", ".iso", ".vmdk", ".qcow2", ".dd", ".E01"):
            self.analyze_disk(file_path)

        return self.findings

    def _file_type(self, path: str) -> None:
        """Identify file type."""
        stdout, _, _ = _run_cmd(["file", path])
        finding = ForensicFinding(tool="file", finding_type="file_type", value=stdout.strip())
        self.findings.append(finding)
        print(f"  [file] {stdout.strip()}")

    def _strings(self, path: str) -> None:
        """Extract strings and search for flags."""
        stdout, _, _ = _run_cmd(["strings", path])
        flags = _extract_flags(stdout)
        if flags:
            for f in flags:
                finding = ForensicFinding(
                    tool="strings",
                    finding_type="flag",
                    value=f,
                    is_flag=True,
                )
                self.findings.append(finding)
                print(f"  [strings] [FLAG] {f}")

        interesting = re.findall(
            r"(?:password|secret|key|token|admin|root|flag)[=:]\s*\S+", stdout, re.IGNORECASE
        )
        for match in interesting[:10]:
            finding = ForensicFinding(tool="strings", finding_type="credential", value=match)
            self.findings.append(finding)
            print(f"  [strings] {match}")

    def _binwalk(self, path: str) -> None:
        """Run binwalk to find embedded files."""
        stdout, _, rc = _run_cmd(["binwalk", path])
        if rc == 0 and stdout.strip():
            finding = ForensicFinding(
                tool="binwalk", finding_type="embedded_files", value=stdout.strip()[:500]
            )
            self.findings.append(finding)
            print(f"  [binwalk] {stdout.strip()[:200]}")

            _stdout_extract, _, _ = _run_cmd(
                ["binwalk", "-e", "--directory=/tmp/forensics_extract", path]
            )
            if os.path.exists("/tmp/forensics_extract"):
                for root, _, files in os.walk("/tmp/forensics_extract"):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        with open(fpath, "rb") as f:
                            content = f.read().decode("utf-8", errors="replace")
                        flags = _extract_flags(content)
                        if flags:
                            for fl in flags:
                                self.findings.append(
                                    ForensicFinding(
                                        tool="binwalk",
                                        finding_type="flag_in_extracted",
                                        value=fl,
                                        is_flag=True,
                                    )
                                )
                                print(f"  [binwalk] [FLAG] {fl}")

    def _exiftool(self, path: str) -> None:
        """Extract EXIF metadata."""
        stdout, _, rc = _run_cmd(["exiftool", path])
        if rc == 0 and stdout.strip():
            finding = ForensicFinding(
                tool="exiftool", finding_type="metadata", value=stdout.strip()[:500]
            )
            self.findings.append(finding)

            flags = _extract_flags(stdout)
            if flags:
                for f in flags:
                    self.findings.append(
                        ForensicFinding(
                            tool="exiftool",
                            finding_type="flag_in_metadata",
                            value=f,
                            is_flag=True,
                        )
                    )
                    print(f"  [exiftool] [FLAG] {f}")

    def analyze_pcap(self, path: str) -> None:
        """Analyze PCAP file for credentials and flags."""
        print(f"  [*] Analyzing PCAP: {path}")

        # tshark HTTP requests
        stdout, _, _ = _run_cmd(
            [
                "tshark",
                "-r",
                path,
                "-Y",
                "http.request",
                "-T",
                "fields",
                "-e",
                "http.request.method",
                "-e",
                "http.host",
                "-e",
                "http.request.uri",
            ]
        )
        if stdout.strip():
            finding = ForensicFinding(
                tool="tshark", finding_type="http_requests", value=stdout.strip()[:500]
            )
            self.findings.append(finding)
            print("  [tshark] HTTP requests found")

        # HTTP credentials (Basic Auth)
        stdout, _, _ = _run_cmd(
            [
                "tshark",
                "-r",
                path,
                "-Y",
                "http.authorization",
                "-T",
                "fields",
                "-e",
                "http.authorization",
            ]
        )
        if stdout.strip():
            finding = ForensicFinding(
                tool="tshark", finding_type="http_credentials", value=stdout.strip()
            )
            self.findings.append(finding)
            print(f"  [tshark] HTTP credentials found: {stdout.strip()[:100]}")

        # FTP credentials
        stdout, _, _ = _run_cmd(
            [
                "tshark",
                "-r",
                path,
                "-Y",
                "ftp.request.command == USER or ftp.request.command == PASS",
                "-T",
                "fields",
                "-e",
                "ftp.request.command",
                "-e",
                "ftp.request.arg",
            ]
        )
        if stdout.strip():
            finding = ForensicFinding(
                tool="tshark", finding_type="ftp_credentials", value=stdout.strip()
            )
            self.findings.append(finding)
            print(f"  [tshark] FTP credentials: {stdout.strip()[:100]}")

        # DNS queries
        stdout, _, _ = _run_cmd(
            [
                "tshark",
                "-r",
                path,
                "-Y",
                "dns.qry.name",
                "-T",
                "fields",
                "-e",
                "dns.qry.name",
            ]
        )
        if stdout.strip():
            domains = list(set(stdout.strip().split("\n")))
            finding = ForensicFinding(
                tool="tshark", finding_type="dns_queries", value=str(domains[:20])
            )
            self.findings.append(finding)

        # Search all pcap text for flags
        stdout, _, _ = _run_cmd(["tshark", "-r", path, "-T", "text"])
        flags = _extract_flags(stdout)
        if flags:
            for f in flags:
                self.findings.append(
                    ForensicFinding(
                        tool="tshark",
                        finding_type="flag_in_pcap",
                        value=f,
                        is_flag=True,
                    )
                )
                print(f"  [tshark] [FLAG] {f}")

    def analyze_image(self, path: str) -> None:
        """Analyze image for steganography."""
        print(f"  [*] Analyzing image: {path}")

        # zsteg for PNG/BMP
        stdout, _, rc = _run_cmd(["zsteg", path])
        if rc == 0 and stdout.strip():
            finding = ForensicFinding(
                tool="zsteg", finding_type="stego_zsteg", value=stdout.strip()[:500]
            )
            self.findings.append(finding)
            print(f"  [zsteg] {stdout.strip()[:200]}")

            flags = _extract_flags(stdout)
            if flags:
                for f in flags:
                    self.findings.append(
                        ForensicFinding(
                            tool="zsteg",
                            finding_type="flag_in_stego",
                            value=f,
                            is_flag=True,
                        )
                    )
                    print(f"  [zsteg] [FLAG] {f}")

        # steghide for JPEG (needs password)
        stdout, stderr, _ = _run_cmd(["steghide", "extract", "-sf", path, "-p", "", "-f"])
        if "wrote extracted data" in (stdout + stderr).lower():
            finding = ForensicFinding(
                tool="steghide",
                finding_type="stego_steghide",
                value="Extracted with empty password",
            )
            self.findings.append(finding)
            print("  [steghide] Extracted with empty password")

        for password in ["password", "admin", "secret", "123456", "flag"]:
            stdout, stderr, _ = _run_cmd(["steghide", "extract", "-sf", path, "-p", password, "-f"])
            if "wrote extracted data" in (stdout + stderr).lower():
                finding = ForensicFinding(
                    tool="steghide",
                    finding_type="stego_steghide",
                    value=f"Extracted with password: {password}",
                )
                self.findings.append(finding)
                print(f"  [steghide] Extracted with password: {password}")
                break

        # stegseek for JPEG (bruteforce)
        stdout, _, _ = _run_cmd(["stegseek", path, "/usr/share/wordlists/rockyou.txt"])
        if "Found password" in stdout:
            finding = ForensicFinding(
                tool="stegseek", finding_type="stego_bruteforce", value=stdout.strip()[:200]
            )
            self.findings.append(finding)
            print(f"  [stegseek] {stdout.strip()[:200]}")

    def analyze_memory(self, path: str) -> None:
        """Analyze memory dump using volatility."""
        print(f"  [*] Analyzing memory dump: {path}")

        # Try volatility 3
        stdout, _, rc = _run_cmd(["volatility3", "-f", path, "linux.pslist.PsList"])
        if rc != 0:
            stdout, _, rc = _run_cmd(["vol.py", "-f", path, "linux.pslist.PsList"])

        if rc == 0 and stdout.strip():
            finding = ForensicFinding(
                tool="volatility", finding_type="processes", value=stdout.strip()[:500]
            )
            self.findings.append(finding)
            print("  [volatility] Processes found")

        # Search for credentials
        stdout, _, rc = _run_cmd(["volatility3", "-f", path, "windows.hashdump.HashDump"])
        if rc == 0 and stdout.strip():
            finding = ForensicFinding(
                tool="volatility", finding_type="password_hashes", value=stdout.strip()[:500]
            )
            self.findings.append(finding)
            print("  [volatility] Password hashes found")

        # Search for flags in memory
        stdout, _, _ = _run_cmd(["strings", path])
        flags = _extract_flags(stdout)
        if flags:
            for f in flags:
                self.findings.append(
                    ForensicFinding(
                        tool="volatility",
                        finding_type="flag_in_memory",
                        value=f,
                        is_flag=True,
                    )
                )
                print(f"  [volatility] [FLAG] {f}")

    def analyze_disk(self, path: str) -> None:
        """Analyze disk image."""
        print(f"  [*] Analyzing disk image: {path}")

        # List partitions
        stdout, _, _ = _run_cmd(["fdisk", "-l", path])
        if stdout.strip():
            finding = ForensicFinding(
                tool="fdisk", finding_type="partitions", value=stdout.strip()[:500]
            )
            self.findings.append(finding)
            print("  [fdisk] Partitions found")

        # Mount and enumerate
        mount_point = "/tmp/disk_mount"
        os.makedirs(mount_point, exist_ok=True)
        stdout, _, _ = _run_cmd(["mount", "-o", "loop,ro", path, mount_point])
        if os.path.ismount(mount_point):
            for root, _, files in os.walk(mount_point):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    if any(
                        kw in fname.lower()
                        for kw in ["flag", "secret", "password", "key", "shadow"]
                    ):
                        try:
                            with open(fpath, "rb") as f:
                                content = f.read(4096).decode("utf-8", errors="replace")
                            flags = _extract_flags(content)
                            finding = ForensicFinding(
                                tool="disk",
                                finding_type="interesting_file",
                                value=f"{fpath}: {content[:200]}",
                                is_flag=bool(flags),
                                details={"flags": flags} if flags else {},
                            )
                            self.findings.append(finding)
                            if flags:
                                print(f"  [disk] [FLAG] {fpath}: {flags}")
                            else:
                                print(f"  [disk] Interesting: {fpath}")
                        except Exception:
                            pass
            _run_cmd(["umount", mount_point])

    def get_flags(self) -> list[str]:
        """Return all flags found."""
        return [f.value for f in self.findings if f.is_flag]

    def get_results(self) -> list[dict[str, Any]]:
        """Return all findings as dicts."""
        return [f.to_dict() for f in self.findings]
