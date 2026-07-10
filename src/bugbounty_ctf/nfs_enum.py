"""NFS enumeration — exports, deeper/sibling mounts, and sensitive-file scan.

Black-box NFS recon, surfaced by a live engagement where the advertised export
was a dead end but the box really wanted a deeper path. This module:

- lists exports (``showmount``),
- proposes parent/sibling mount candidates many servers serve but don't
  advertise (e.g. ``/srv/nfs`` parent, ``/home``),
- mounts read-only inside the container by default (the mount syscall needs
  root; ``KaliEnv`` provides it without touching host root), and
- scans a mounted share for SSH keys, configs, and credentials — plus files
  it cannot read, reporting the owner UID to spoof (the classic NFS AUTH_SYS
  trick) so the operator can re-read as that UID.

Privileged ops (``showmount``, ``mount``) run through an injected ``ExecEnv``
that defaults to ``KaliEnv`` — the container is the default substrate, so the
agent never needs to hand-route a mount through kalibox. For ``KaliEnv`` the
share is mounted and scanned *inside* the container (an NFS submount under the
``rprivate`` ``/work`` bind mount does not propagate to the host, so the loot is
only visible in-container); ``scan_dir`` stays pure host-filesystem code for the
``HostEnv`` path and back-compat.

Usage:
    from bugbounty_ctf.nfs_enum import NFSEnumerator

    nfs = NFSEnumerator("10.10.10.10")        # container execution by default
    exports = nfs.list_exports()
    for path in nfs.candidate_mounts(exports):
        print("try:", path)
    # mount in the container + scan the loot from the host in one call:
    report = nfs.mount_and_scan("/srv/nfs/onboarding")
    print(report["scan"]["ssh_keys"], report["scan"]["uid_locked"])
"""

from __future__ import annotations

import importlib.resources
import json
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bugbounty_ctf import nfs_scan
from bugbounty_ctf.execenv import ExecEnv, HostEnv, KaliEnv, default_exec_env

# Common unadvertised export roots worth probing beyond what showmount returns.
_COMMON_ROOTS = ("/home", "/srv/nfs", "/srv", "/var/nfs", "/exports", "/mnt", "/opt", "/data")

_HOST_RE = re.compile(r"^[A-Za-z0-9._:\-\[\]]+$")
_HOST_MOUNT_ROOT = "bugbounty_ctf_nfs"


@dataclass
class NFSExport:
    path: str
    clients: str = "*"

    def to_dict(self) -> dict[str, str]:
        return {"path": self.path, "clients": self.clients}


class NFSEnumerator:
    """Enumerate and analyse NFS exports for a host."""

    def __init__(self, host: str, *, env: ExecEnv | None = None) -> None:
        if not _HOST_RE.match(host):
            raise ValueError(f"Invalid NFS host: {host!r}")
        self.host = host
        # Privileged/raw ops default to the container (KaliEnv); pure host-fs
        # analysis (scan_dir) never touches env.
        self.env = env or default_exec_env()

    def _exec(self, argv: list[str], *, timeout: float = 20) -> tuple[str, str, int]:
        """Run an argv in the env, never raising (returns rc=-1 on failure)."""
        try:
            r = self.env.run(argv, timeout=timeout)
            return r.stdout, r.stderr, r.returncode
        except (OSError, subprocess.SubprocessError) as exc:
            return "", str(exc), -1
        except Exception as exc:
            return "", str(exc), -1

    def list_exports(self) -> list[NFSExport]:
        """Return advertised exports via ``showmount -e`` (empty if none/blocked)."""
        out, _, rc = self._exec(["showmount", "-e", "--no-headers", self.host])
        if rc != 0 and not out:
            out, _, _ = self._exec(["showmount", "-e", self.host])
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

        ``mountpoint`` is interpreted **in the env**. With the default
        ``KaliEnv``, pass a container path that is NOT under ``/work`` (e.g.
        ``/mnt/nfs_nfs``): the mount runs as root inside the container and the
        loot is visible *in the container* only — an NFS submount under the
        ``rprivate`` ``/work`` bind mount would not propagate to the host, so
        the share is scanned in-container instead of via ``host_path``.
        With ``HostEnv`` it is an ordinary host path (created here).

        Returns ``{remote, mountpoint, mounted, error}`` and never raises, so
        callers can sweep candidates and report what needs privilege.
        """
        remote = f"{self.host}:{remote_path}"
        # Only create the directory for host-side mounts; container paths under
        # /work live inside the container's namespace.
        if isinstance(self.env, HostEnv):
            try:
                os.makedirs(mountpoint, exist_ok=True)
            except OSError as exc:
                return {
                    "remote": remote,
                    "mountpoint": mountpoint,
                    "mounted": False,
                    "error": f"mountpoint directory error: {exc}",
                }
        opts = f"vers={vers},nolock" + (",ro" if read_only else "")
        _, err, rc = self._exec(
            ["mount", "-t", "nfs", "-o", opts, remote, mountpoint],
            timeout=25,
        )
        return {
            "remote": remote,
            "mountpoint": mountpoint,
            "mounted": rc == 0,
            "error": err.strip() if rc != 0 else "",
        }

    def mount_and_scan(self, remote_path: str, *, name: str = "nfs") -> dict[str, Any]:
        """Mount ``remote_path`` in the env and scan the loot where it is visible.

        For a ``KaliEnv`` the share is mounted at ``/mnt/nfs_{name}`` *inside*
        the container (NOT under ``/work``, whose ``rprivate`` bind mount would
        hide the submount from the host). The standalone scanner is copied into
        the container via the ``/work`` bind mount and run there, and its JSON
        report is parsed back. For a ``HostEnv`` the share is mounted under a
        deterministic host temp directory and scanned directly via ``scan_dir``.

        Returns ``{"mount": <try_mount result>, "scan": <report|None>}`` — scan
        is ``None`` if the mount failed or the in-container scan output could not
        be parsed. Never raises.
        """
        if isinstance(self.env, KaliEnv):
            return self._mount_and_scan_container(remote_path, name=name)
        try:
            base = (Path(tempfile.gettempdir()) / _HOST_MOUNT_ROOT).resolve(strict=False)
            mountpoint_path = (base / name).resolve(strict=False)
        except OSError as exc:
            mount = {
                "remote": f"{self.host}:{remote_path}",
                "mountpoint": "",
                "mounted": False,
                "error": f"host mountpoint error: {exc}",
            }
            return {"mount": mount, "scan": None}
        if mountpoint_path != base and not mountpoint_path.is_relative_to(base):
            mount = {
                "remote": f"{self.host}:{remote_path}",
                "mountpoint": str(base),
                "mounted": False,
                "error": f"Invalid mount name: {name!r}",
            }
            return {"mount": mount, "scan": None}
        mountpoint = str(mountpoint_path)
        mount = self.try_mount(remote_path, mountpoint)
        scan = self.scan_dir(mountpoint) if mount["mounted"] else None
        return {"mount": mount, "scan": scan}

    def _mount_and_scan_container(self, remote_path: str, *, name: str) -> dict[str, Any]:
        """KaliEnv path: mount in-container at ``/mnt/nfs_{name}`` and scan there."""
        env = self.env
        assert isinstance(env, KaliEnv)  # guarded by caller
        mountpoint = f"/mnt/nfs_{name}"
        mount = self.try_mount(remote_path, mountpoint)
        scan: dict[str, Any] | None = None
        if mount["mounted"]:
            scan = self._run_container_scan(mountpoint)
        return {"mount": mount, "scan": scan}

    def _run_container_scan(self, mountpoint: str) -> dict[str, Any] | None:
        """Copy the standalone scanner into the container and run it there."""
        env = self.env
        assert isinstance(env, KaliEnv)
        try:
            source = importlib.resources.files(nfs_scan.__package__) / "nfs_scan.py"
            script_bytes = source.read_bytes()
        except (OSError, FileNotFoundError, TypeError):
            try:
                with open(nfs_scan.__file__, "rb") as fh:
                    script_bytes = fh.read()
            except OSError:
                return None
        # Write the scanner into the host workdir, which appears at /work
        # inside the container via the bind mount.
        host_script = os.path.join(env.workdir, "_nfs_scan.py")
        try:
            os.makedirs(env.workdir, exist_ok=True)
            with open(host_script, "wb") as fh:
                fh.write(script_bytes)
        except OSError:
            return None
        container_script = f"{KaliEnv.container_workdir}/_nfs_scan.py"
        out, _, rc = self._exec(["python3", container_script, mountpoint])
        if rc != 0 or not out.strip():
            return None
        try:
            parsed = json.loads(out)
        except (ValueError, TypeError):
            return None
        return parsed if isinstance(parsed, dict) else None

    @staticmethod
    def scan_dir(path: str, *, max_files: int = 5000, read_bytes: int = 4096) -> dict[str, Any]:
        """Walk a mounted share for sensitive files and UID-locked content.

        Delegates to :func:`bugbounty_ctf.nfs_scan.scan`; kept as the public
        static method for ``HostEnv`` / back-compat. Returns ``ssh_keys`` /
        ``secrets`` (readable hits), ``uid_locked`` (files we can't read, with
        the owner UID to spoof), and ``interesting`` (all flagged paths). Pure
        filesystem analysis — no privilege needed.
        """
        return nfs_scan.scan(path, max_files=max_files, read_bytes=read_bytes)
