"""execenv — the execution substrate for a single capability.

An ``ExecEnv`` decides *where* a command runs. The point is to make the
container the **default** substrate for anything privileged or raw-network,
so the agent never has to remember to route a mount/spray/scan through
kalibox in prose — it is structural, injected at construction time.

Per-capability boundary:

- **Pure analysis stays on the host.** Walking an already-mounted directory,
  parsing tool output, or talking plain TCP from Python needs no privilege and
  no container — use ``HostEnv`` (or no env at all).
- **Privileged / raw-network ops go to the container by default.** Mounting NFS,
  raw sockets, installing offensive tooling, etc. need host root otherwise, so
  they default to ``KaliEnv`` which runs them inside the disposable Kali
  container with its own namespace and host networking.

Note: kalibox is an operational convenience and a disposable namespace —
**NOT** a security sandbox. A ``--privileged`` container with host networking
is equivalent to host root. The boundary exists to contain *where* root-needing
operations run, not to sandbox untrusted code.

Path mapping: the container bind-mounts a host work dir at ``/work``. A path the
container sees as ``/work/nfs`` is readable on the host at ``<workdir>/nfs``;
``KaliEnv.host_path`` performs that translation so loot mounted inside the
container can be scanned with plain host-filesystem code.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from bugbounty_ctf.kalibox import KaliBox

CONTAINER_WORKDIR = "/work"


@runtime_checkable
class ExecEnv(Protocol):
    """Where a command runs. Implementations decide host vs. container."""

    def run(
        self, argv: Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]: ...


class HostEnv:
    """Run argv directly on the host (list-form, no shell).

    For pure, unprivileged work. The host must already be able to do the
    operation — there is no privilege escalation here.
    """

    def run(
        self, argv: Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout)


class KaliEnv:
    """Run argv inside the disposable Kali container (the default substrate).

    The container is started lazily on first use (``start`` only — no full
    tool provision on every call) and the argv is delegated to
    ``KaliBox.exec_raw`` so it runs as literal argv with no shell.
    """

    container_workdir = CONTAINER_WORKDIR

    def __init__(self, box: KaliBox | None = None) -> None:
        self.box = box or KaliBox()

    @property
    def workdir(self) -> str:
        """Host path bind-mounted to ``/work`` inside the container."""
        return self.box.workdir

    def run(
        self, argv: Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.box.start()
        return self.box.exec_raw(list(argv), timeout=timeout)

    def host_path(self, container_path: str) -> str:
        """Map a container ``/work/...`` path to its host bind-mount path.

        e.g. ``/work/nfs`` → ``<workdir>/nfs``. Raises ``ValueError`` if the
        path is not under ``/work``.
        """
        prefix = self.container_workdir.rstrip("/")
        normalized = container_path.rstrip("/") or "/"
        if normalized != prefix and not normalized.startswith(prefix + "/"):
            raise ValueError(f"Path is not under {prefix!r}: {container_path!r}")
        relative = normalized[len(prefix) :].lstrip("/")
        return f"{self.workdir.rstrip('/')}/{relative}" if relative else self.workdir.rstrip("/")


def default_exec_env() -> ExecEnv:
    """The default substrate for privileged ops: the Kali container."""
    return KaliEnv()
