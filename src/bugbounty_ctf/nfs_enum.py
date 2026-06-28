"""NFS enumeration — exports, deeper/sibling mounts, and sensitive-file scan.

Black-box NFS recon, surfaced by a live engagement where the advertised export
was a dead end but the box really wanted a deeper path. This module:

- lists exports (``showmount``),
- proposes parent/sibling mount candidates many servers serve but don't
  advertise (e.g. ``/srv/nfs`` parent, ``/home``),
- mounts read-only (needs root for the mount itself), and
- scans a mounted share for SSH keys, configs, and credentials — plus files
  it cannot read, reporting the owner UID to spoof (the classic NFS AUTH_SYS
  trick) so the operator can re-read as that UID.

Usage:
    from bugbounty_ctf.nfs_enum import NFSEnumerator

    nfs = NFSEnumerator("10.10.10.10")
    exports = nfs.list_exports()
    for path in nfs.candidate_mounts(exports):
        print("try:", path)
    # after mounting a share read-only:
    report = NFSEnumerator.scan_dir("/mnt/share")
    print(report["ssh_keys"], report["uid_locked"])
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
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

# Common unadvertised export roots worth probing beyond what showmount returns.
_COMMON_ROOTS = ("/home", "/srv/nfs", "/srv", "/var/nfs", "/exports", "/mnt", "/opt", "/data")

_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")


@dataclass
class NFSExport:
    path: str
    clients: str = "*"

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "clients": self.clients}


def _run(cmd: list[str], timeout: int = 20) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "", "", -1


class NFSEnumerator:
    """Enumerate and analyse NFS exports for a host."""

    def __init__(self, host: str) -> None:
        if not _HOST_RE.match(host):
            raise ValueError(f"Invalid NFS host: {host!r}")
        self.host = host

    def list_exports(self) -> list[NFSExport]:
        """Return advertised exports via ``showmount -e`` (empty if none/blocked)."""
        out, _, rc = _run(["showmount", "-e", "--no-headers", self.host])
        if rc != 0 and not out:
            out, _, _ = _run(["showmount", "-e", self.host])
        exports: list[NFSExport] = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.lower().startswith("export list"):
                continue
            parts = line.split()
            path = parts[0]
            clients = " ".join(parts[1:]) if len(parts) > 1 else "*"
            if path.startswith("/"):
                exports.append(NFSExport(path=path, clients=clients))
        return exports

    def candidate_mounts(self, exports: list[NFSExport] | None = None) -> list[str]:
        """Propose mountable paths: each export, its parents, and common roots.

        Many servers serve a parent or sibling path that ``showmount`` omits, so
        these are worth attempting even when not advertised.
        """
        if exports is None:
            exports = self.list_exports()
        seen: set[str] = set()
        candidates: list[str] = []

        def add(p: str) -> None:
            p = p.rstrip("/") or "/"
            if p not in seen:
                seen.add(p)
                candidates.append(p)

        for exp in exports:
            add(exp.path)
            parent = os.path.dirname(exp.path.rstrip("/"))
            while parent and parent != "/":
                add(parent)
                parent = os.path.dirname(parent)
        for root in _COMMON_ROOTS:
            add(root)
        return candidates

    def try_mount(
        self, remote_path: str, mountpoint: str, *, vers: int = 3, read_only: bool = True
    ) -> dict[str, Any]:
        """Mount ``host:remote_path`` at ``mountpoint`` (read-only by default).

        The mount syscall needs root; returns ``{"mounted", "error"}`` and never
        raises, so callers can sweep candidates and report what needs privilege.
        """
        os.makedirs(mountpoint, exist_ok=True)
        opts = f"vers={vers},nolock" + (",ro" if read_only else "")
        _, err, rc = _run(
            ["mount", "-t", "nfs", "-o", opts, f"{self.host}:{remote_path}", mountpoint],
            timeout=25,
        )
        return {
            "remote": f"{self.host}:{remote_path}",
            "mountpoint": mountpoint,
            "mounted": rc == 0,
            "error": err.strip() if rc != 0 else "",
        }

    @staticmethod
    def scan_dir(path: str, *, max_files: int = 5000, read_bytes: int = 4096) -> dict[str, Any]:
        """Walk a mounted share for sensitive files and UID-locked content.

        Returns ``ssh_keys`` / ``secrets`` (readable hits), ``uid_locked``
        (files we can't read, with the owner UID to spoof), and ``interesting``
        (all flagged paths). Pure filesystem analysis — no privilege needed.
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
                    name in _SSH_KEY_NAMES
                    or name in _SECRET_NAMES
                    or name.endswith(_SECRET_SUFFIXES)
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
