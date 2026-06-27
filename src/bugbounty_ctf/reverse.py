"""Reverse engineering module — binary analysis automation.

Handles:
- Binary analysis: strings, symbols, imports, protections
- radare2 automation: disassembly, function listing, cross-references
- Ghidra headless scripting: decompilation, function analysis
- Pattern matching: find crypto constants, hardcoded creds, flags
- Architecture detection and format analysis

Usage:
    from bugbounty_ctf.reverse import ReverseToolkit

    rt = ReverseToolkit("challenge_binary")
    info = rt.analyze()
    funcs = rt.list_functions()
    strings = rt.find_interesting_strings()
    decompiled = rt.decompile_function("main")
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any

FLAG_PATTERNS = [r"HTB\{[^}]+\}", r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"pwn\{[^}]+\}"]

INTERESTING_STRING_PATTERNS = [
    (r"password[=:]\s*\S+", "password"),
    (r"secret[=:]\s*\S+", "secret"),
    (r"api[_-]?key[=:]\s*\S+", "api_key"),
    (r"token[=:]\s*\S+", "token"),
    (r"https?://[^\s]+", "url"),
    (r"/(?:home|Users?|root)/[^\s]+", "filepath"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "ip_address"),
    (r"BEGIN.*PRIVATE KEY", "private_key"),
    (r"SHA-?[0-9]+|MD5|AES|RSA|DES|RC4", "crypto_identifier"),
    (r"system\(|exec\(|popen\(|fork\(|execve\(", "dangerous_function"),
    (r"gets\(|scanf\(|strcpy\(|strcat\(|sprintf\(", "vulnerable_function"),
]

GHIDRA_SCRIPT_TEMPLATE = """
// Ghidra headless analysis script
// @category Analysis
import ghidra.app.decompiler.DecompInterface
import ghidra.app.decompiler.DecompileOptions

decomp = DecompInterface()
decomp.openProgram(currentProgram)

fm = currentProgram.getFunctionManager()
funcs = fm.getFunctions(True)

for func in funcs:
    results = decomp.decompileFunction(func, 30, monitor)
    if results and results.getDecompiledFunction():
        code = results.getDecompiledFunction().getC()
        println("=== " + func.getName() + " ===")
        println(code)
"""


@dataclass
class REFinding:
    """A finding from reverse engineering analysis."""

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
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "", "", -1


class ReverseToolkit:
    """Reverse engineering automation for CTF binary challenges."""

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path
        self.findings: list[REFinding] = []
        self.arch: str = "unknown"
        self.format_type: str = "unknown"

    def analyze(self) -> dict[str, Any]:
        """Run full analysis on the binary."""
        self.findings = []

        if not os.path.exists(self.binary_path):
            print(f"[-] Binary not found: {self.binary_path}")
            return {}

        self.file_info()
        self.checksec()
        self.strings_analysis()
        self.symbol_analysis()
        self.radare2_analysis()
        self.find_flags()

        return self.get_results()

    def file_info(self) -> dict[str, str]:
        """Get file type information."""
        stdout, _, _ = _run_cmd(["file", self.binary_path])
        info = stdout.strip()

        if "ELF" in info:
            self.format_type = "ELF"
        elif "PE32" in info or "MS-DOS" in info:
            self.format_type = "PE"
        elif "Mach-O" in info:
            self.format_type = "Mach-O"

        if "x86-64" in info or "x86_64" in info:
            self.arch = "amd64"
        elif "x86" in info or "i386" in info:
            self.arch = "i386"
        elif "ARM" in info:
            self.arch = "arm"
        elif "aarch64" in info:
            self.arch = "aarch64"

        self.findings.append(
            REFinding(
                tool="file",
                finding_type="file_info",
                value=info,
                details={"format": self.format_type, "arch": self.arch},
            )
        )
        print(f"  [file] {info}")
        print(f"    Format: {self.format_type}, Arch: {self.arch}")

        return {"format": self.format_type, "arch": self.arch, "info": info}

    def checksec(self) -> dict[str, bool]:
        """Check binary protections."""
        stdout, stderr, _ = _run_cmd(["checksec", f"--file={self.binary_path}"])
        output = stdout + stderr

        protections = {
            "nx": "NX enabled" in output,
            "pie": "PIE enabled" in output,
            "canary": "Canary found" in output,
            "relro": "Full RELRO" in output,
            "fortify": "FORTIFY" in output,
        }

        self.findings.append(
            REFinding(
                tool="checksec",
                finding_type="protections",
                value=str(protections),
                details=protections,
            )
        )
        for k, v in protections.items():
            print(f"    {k}: {v}")

        return protections

    def strings_analysis(self) -> list[dict[str, str]]:
        """Extract and analyze strings from the binary."""
        stdout, _, _ = _run_cmd(["strings", "-n", "4", self.binary_path])

        flags = _extract_flags(stdout)
        for flag in flags:
            self.findings.append(
                REFinding(
                    tool="strings",
                    finding_type="flag",
                    value=flag,
                    is_flag=True,
                    details={"flags": flags},
                )
            )
            print(f"  [strings] [FLAG] {flag}")

        interesting: list[dict[str, str]] = []
        for pattern, ptype in INTERESTING_STRING_PATTERNS:
            matches = re.findall(pattern, stdout, re.IGNORECASE)
            if matches:
                for match in set(matches):
                    finding = {"type": ptype, "value": match[:100]}
                    interesting.append(finding)
                    self.findings.append(
                        REFinding(
                            tool="strings",
                            finding_type=ptype,
                            value=match[:200],
                            details=finding,
                        )
                    )
                    print(f"  [strings] {ptype}: {match[:80]}")

        return interesting

    def symbol_analysis(self) -> dict[str, list[str]]:
        """Analyze symbols using nm or objdump."""
        stdout, _, rc = _run_cmd(["nm", self.binary_path])
        symbols: dict[str, list[str]] = {"functions": [], "variables": [], "imports": []}

        if rc == 0 and stdout.strip():
            for line in stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 3:
                    sym_type = parts[1]
                    name = parts[2]
                    if sym_type in ("T", "t"):
                        symbols["functions"].append(name)
                    elif sym_type in ("D", "d", "B", "b", "R", "r"):
                        symbols["variables"].append(name)
                    elif sym_type == "U":
                        symbols["imports"].append(name)

            self.findings.append(
                REFinding(
                    tool="nm",
                    finding_type="symbols",
                    value=f"functions={len(symbols['functions'])}, imports={len(symbols['imports'])}",
                    details=symbols,
                )
            )
            print(
                f"  [nm] {len(symbols['functions'])} functions, "
                f"{len(symbols['imports'])} imports, {len(symbols['variables'])} variables"
            )

            for imp in symbols["imports"]:
                if any(
                    kw in imp.lower() for kw in ["system", "exec", "popen", "fork", "gets", "scanf"]
                ):
                    print(f"    [!] Interesting import: {imp}")

        return symbols

    def radare2_analysis(self) -> dict[str, Any]:
        """Run radare2 analysis commands."""
        print("  [*] radare2 analysis...")

        results: dict[str, Any] = {}

        # List functions
        stdout, _, _ = _run_cmd(
            [
                "r2",
                "-q",
                "-c",
                "aaa; afl",
                self.binary_path,
            ],
            timeout=60,
        )
        if stdout.strip():
            functions = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
            results["functions"] = functions[:50]
            print(f"    [r2] {len(functions)} functions found")

        # List imports
        stdout, _, _ = _run_cmd(
            [
                "r2",
                "-q",
                "-c",
                "ii",
                self.binary_path,
            ],
            timeout=30,
        )
        if stdout.strip():
            imports = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
            results["imports"] = imports[:30]
            print(f"    [r2] {len(imports)} imports found")

        # Search for crypto constants
        stdout, _, _ = _run_cmd(
            [
                "r2",
                "-q",
                "-c",
                "/x 67452301; /x 0123456789ABCDEF",
                self.binary_path,
            ],
            timeout=30,
        )
        if stdout.strip():
            results["crypto_constants"] = stdout.strip()[:200]
            print("    [r2] Crypto constants found")

        if results:
            self.findings.append(
                REFinding(
                    tool="radare2",
                    finding_type="analysis",
                    value=f"functions={len(results.get('functions', []))}",
                    details=results,
                )
            )

        return results

    def decompile_function(self, function_name: str) -> str:
        """Decompile a function using radare2 pdc or Ghidra."""
        stdout, _, _ = _run_cmd(
            [
                "r2",
                "-q",
                "-c",
                f"aaa; s sym.{function_name}; pdc",
                self.binary_path,
            ],
            timeout=60,
        )

        if stdout.strip():
            print(f"  [r2] Decompiled {function_name} ({len(stdout)} chars)")
            self.findings.append(
                REFinding(
                    tool="radare2",
                    finding_type="decompilation",
                    value=stdout[:500],
                    details={"function": function_name},
                )
            )
            return stdout

        return self.ghidra_decompile(function_name)

    def ghidra_decompile(self, function_name: str) -> str:
        """Decompile using Ghidra headless mode."""
        ghidra_path = os.environ.get("GHIDRA_HOME", "")
        if not ghidra_path or not os.path.exists(ghidra_path):
            return ""

        script_path = "/tmp/ghidra_decompile.py"
        with open(script_path, "w") as f:
            f.write(GHIDRA_SCRIPT_TEMPLATE)

        stdout, _, _ = _run_cmd(
            [
                f"{ghidra_path}/support/analyzeHeadless",
                "/tmp/ghidra_project",
                "temp_proj",
                "-import",
                self.binary_path,
                "-postScript",
                script_path,
                "-delete",
            ],
            timeout=120,
        )

        if stdout.strip():
            self.findings.append(
                REFinding(
                    tool="ghidra",
                    finding_type="decompilation",
                    value=stdout[:500],
                    details={"function": function_name},
                )
            )
            print(f"  [ghidra] Decompiled output ({len(stdout)} chars)")

        return stdout

    def find_flags(self) -> list[str]:
        """Search the binary for flag patterns using multiple methods."""
        flags: list[str] = []

        # strings + grep
        stdout, _, _ = _run_cmd(["strings", self.binary_path])
        flags.extend(_extract_flags(stdout))

        # r2 search for flag patterns
        for pattern in FLAG_PATTERNS:
            escaped = pattern.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")
            stdout, _, _ = _run_cmd(
                [
                    "r2",
                    "-q",
                    "-c",
                    f"/ {escaped}",
                    self.binary_path,
                ],
                timeout=10,
            )
            if stdout.strip():
                flags.extend(_extract_flags(stdout))

        flags = list(set(flags))
        if flags:
            for flag in flags:
                self.findings.append(
                    REFinding(
                        tool="flag_search",
                        finding_type="flag",
                        value=flag,
                        is_flag=True,
                    )
                )
                print(f"  [FLAG] {flag}")

        return flags

    def disassemble_function(self, function_name: str) -> str:
        """Disassemble a function using objdump or r2."""
        stdout, _, _ = _run_cmd(
            [
                "r2",
                "-q",
                "-c",
                f"aaa; s sym.{function_name}; pdf",
                self.binary_path,
            ],
            timeout=30,
        )

        if stdout.strip():
            self.findings.append(
                REFinding(
                    tool="radare2",
                    finding_type="disassembly",
                    value=stdout[:500],
                    details={"function": function_name},
                )
            )
            return stdout

        stdout, _, _ = _run_cmd(
            [
                "objdump",
                "-d",
                self.binary_path,
            ]
        )
        if stdout:
            func_section = ""
            in_func = False
            for line in stdout.split("\n"):
                if f"<{function_name}>:" in line:
                    in_func = True
                    func_section += line + "\n"
                elif in_func:
                    if line.strip() == "" or ("<" in line and ">:" in line):
                        break
                    func_section += line + "\n"
            if func_section:
                return func_section

        return ""

    def get_results(self) -> dict[str, Any]:
        """Return all findings."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "flags": [f.value for f in self.findings if f.is_flag],
            "arch": self.arch,
            "format": self.format_type,
        }
