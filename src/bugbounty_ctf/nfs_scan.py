"""Standalone NFS share scanner — stdlib-only, zero package dependencies.

This module is intentionally self-contained: it imports nothing from
``bugbounty_ctf`` so it can be copied verbatim into the Kali container (via the
bind mount) and run there with a bare ``python3``. That matters because an NFS
submount made *inside* the container does not propagate back to the host
bind-mount (``rprivate`` propagation), so the loot is only visible in-container —
the scan has to run where the mount actually is.

The scan walks a directory for SSH keys, configs, and credentials, plus files it
cannot read (reporting the owner UID to spoof — the classic NFS AUTH_SYS trick).

Run standalone::

    python3 nfs_scan.py /mnt/nfs_share
"""

from __future__ import annotations

import os
import re
from typing import Any

# Names worth flagging when found on a share.
_SSH_KEY_NAMES = ("id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", "authorized_keys")
_SECRET_NAMES = (
    ".env",
    "credentials",
    "config.php",
    "settings.py",
    "wp-config.php",
    ".htpasswd",
    ".git-credentials",
    "shadow",
    "user.txt",
    "root.txt",
)
_SECRET_SUFFIXES = (".pem", ".key", ".kdbx", ".bak", ".ovpn", ".ppk")
_SECRET_CONTENT = re.compile(
    r"PRIVATE KEY|BEGIN OPENSSH|ssh-(rsa|ed25519|dss)|password\s*[:=]|passwd\s*[:=]",
    re.IGNORECASE,
)


def scan(path: str, *, max_files: int = 5000, read_bytes: int = 4096) -> dict[str, Any]:
    """Walk a mounted share for sensitive files and UID-locked content.

    Returns ``ssh_keys`` / ``secrets`` (readable hits), ``uid_locked`` (files we
    can't read, with the owner UID to spoof), and ``interesting`` (all flagged
    paths). Pure filesystem analysis — no privilege needed.
    """
    report: dict[str, Any] = {
        "root": path,
        "ssh_keys": [],
        "secrets": [],
        "uid_locked": [],
        "interesting": [],
    }
    count = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            count += 1
            if count > max_files:
                return report
            full = os.path.join(root, name)
            flagged = (
                name in _SSH_KEY_NAMES or name in _SECRET_NAMES or name.endswith(_SECRET_SUFFIXES)
            )
            try:
                st = os.stat(full)
            except OSError:
                continue
            readable = os.access(full, os.R_OK)
            entry = {"path": full, "uid": st.st_uid, "size": st.st_size, "readable": readable}

            if not readable:
                report["uid_locked"].append(entry)  # spoof entry["uid"] to read
                continue

            hit = flagged
            if not hit and st.st_size <= read_bytes * 4:
                try:
                    with open(full, encoding="utf-8", errors="ignore") as fh:
                        if _SECRET_CONTENT.search(fh.read(read_bytes)):
                            hit = True
                except OSError:
                    pass
            if hit:
                report["interesting"].append(entry)
                if name in _SSH_KEY_NAMES or name.endswith((".pem", ".key", ".ppk")):
                    report["ssh_keys"].append(entry)
                else:
                    report["secrets"].append(entry)
    return report


if __name__ == "__main__":
    import json
    import sys

    print(json.dumps(scan(sys.argv[1])))
