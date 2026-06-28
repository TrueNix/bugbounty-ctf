"""kalibox — run offensive tooling inside an isolated Kali container.

Keeps root and privilege **off the host**. A persistent, privileged Kali
container with host networking (so it sees your VPN and reaches engagement
targets like ``10.129.x.x``) executes the offensive tooling — ``nmap``, NFS
mounts, ``smbclient``, sprays, etc. — via ``docker exec``. The host never runs
``sudo`` and never grants the agent root; all privilege lives inside a
disposable container you can destroy at any time.

Why this exists: agents reach for host ``sudo`` / ``docker --privileged`` to do
things like mount NFS, which means handing them root on your machine. Routing
everything through ``kalibox`` removes that need entirely.

Usage (Python):
    from bugbounty_ctf.kalibox import KaliBox

    box = KaliBox().ensure()                 # pull image, start, install tools (once)
    r = box.run("nmap -sCV -p- 10.129.33.77")
    print(r.stdout)
    box.run(["mount", "-t", "nfs", "-o", "vers=3,ro", "10.129.33.77:/srv/nfs/x", "/work/nfs"])

Usage (CLI, installed as the ``kalibox`` entry point):
    kalibox up                 # provision + start the container
    kalibox nmap -sCV 10.129.33.77
    kalibox shell              # interactive Kali shell
    kalibox status
    kalibox destroy            # tear it down
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Callable, Sequence
from typing import Any

DEFAULT_IMAGE = "kalilinux/kali-rolling"
DEFAULT_NAME = "kalibox"
DEFAULT_RUNTIME = "docker"
DEFAULT_WORKDIR = os.path.expanduser("~/.hermes/kalibox/work")

# Baseline offensive toolset installed once on first provision.
DEFAULT_TOOLS: tuple[str, ...] = (
    "nmap",
    "nfs-common",
    "smbclient",
    "netcat-traditional",
    "curl",
    "wget",
    "iproute2",
    "dnsutils",
    "iputils-ping",
    "ftp",
    "snmp",
    "ldap-utils",
    "redis-tools",
    "hydra",
    "gobuster",
    "ffuf",
    "seclists",
    "python3",
    "python3-pip",
)

_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_PROVISION_MARKER = "/var/lib/.kalibox-provisioned"

# Runner signature mirrors a thin subprocess.run wrapper so it can be injected
# in tests without touching the real container runtime.
Runner = Callable[..., "subprocess.CompletedProcess[str]"]


def _default_runner(
    cmd: Sequence[str], *, timeout: float | None = None, input: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout, input=input)


class KaliBox:
    """Manage and execute commands in an isolated Kali attack container."""

    class DockerNotFoundError(RuntimeError):
        """Raised when the container runtime binary is not on PATH."""

    def __init__(
        self,
        *,
        name: str = DEFAULT_NAME,
        image: str = DEFAULT_IMAGE,
        workdir: str = DEFAULT_WORKDIR,
        runtime: str = DEFAULT_RUNTIME,
        runner: Runner | None = None,
    ) -> None:
        if not _NAME_RE.match(name):
            raise ValueError(f"Invalid container name: {name!r}")
        if not _NAME_RE.match(runtime):
            raise ValueError(f"Invalid runtime: {runtime!r}")
        self.name = name
        self.image = image
        self.workdir = workdir
        self.runtime = runtime
        self._run = runner or _default_runner

    # ------------------------------------------------------------------ runtime
    def _runtime(
        self, args: Sequence[str], *, timeout: float | None = None, input: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Invoke the container runtime (list-form, no shell)."""
        try:
            return self._run([self.runtime, *args], timeout=timeout, input=input)
        except FileNotFoundError as e:
            raise self.DockerNotFoundError(
                f"`{self.runtime}` not found on PATH — cannot use kalibox"
            ) from e

    def exists(self) -> bool:
        """True if the container exists (running or stopped)."""
        r = self._runtime(["ps", "-a", "--filter", f"name=^{self.name}$", "--format", "{{.Names}}"])
        return self.name in (r.stdout or "").split()

    def is_running(self) -> bool:
        """True if the container is currently running."""
        r = self._runtime(["ps", "--filter", f"name=^{self.name}$", "--format", "{{.Names}}"])
        return self.name in (r.stdout or "").split()

    def has_image(self) -> bool:
        r = self._runtime(["images", "-q", self.image])
        return bool((r.stdout or "").strip())

    def pull(self) -> subprocess.CompletedProcess[str]:
        return self._runtime(["pull", self.image], timeout=900)

    # --------------------------------------------------------------- lifecycle
    def start(self) -> None:
        """Start the persistent container, creating it (and pulling) if needed.

        The container runs ``--privileged --network host`` so NFS mounts work in
        its own namespace and it sees the host VPN — but the host itself is never
        asked for root. A host work dir is bind-mounted at ``/work`` so loot is
        retrievable without ``docker cp``.
        """
        if self.is_running():
            return
        if self.exists():
            self._runtime(["start", self.name])
            return
        os.makedirs(self.workdir, exist_ok=True)
        if not self.has_image():
            self.pull()
        self._runtime(
            [
                "run",
                "-d",
                "--name",
                self.name,
                "--privileged",
                "--network",
                "host",
                "-v",
                f"{self.workdir}:/work",
                "-w",
                "/work",
                "--restart",
                "unless-stopped",
                self.image,
                "sleep",
                "infinity",
            ],
            timeout=180,
        )

    def provision(self, tools: Sequence[str] = DEFAULT_TOOLS) -> bool:
        """Install the baseline toolset once. Returns True if it installed now.

        Idempotent: a marker file inside the container short-circuits subsequent
        calls, so re-running ``ensure()`` is cheap.
        """
        if self.exec_raw(["test", "-f", _PROVISION_MARKER]).returncode == 0:
            return False
        script = (
            "apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y "
            + " ".join(tools)
            + f" && touch {_PROVISION_MARKER}"
        )
        self.exec_raw(["bash", "-lc", script], timeout=2400)
        return True

    def ensure(self, *, provision: bool = True) -> KaliBox:
        """Bring the container up (and provision the toolset) — the entry point."""
        self.start()
        if provision:
            self.provision()
        return self

    def stop(self) -> subprocess.CompletedProcess[str]:
        return self._runtime(["stop", self.name])

    def destroy(self) -> subprocess.CompletedProcess[str]:
        """Remove the container entirely (host work dir is left intact)."""
        return self._runtime(["rm", "-f", self.name])

    def status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "image": self.image,
            "runtime": self.runtime,
            "exists": self.exists(),
            "running": self.is_running(),
            "workdir": self.workdir,
        }

    # --------------------------------------------------------------- execution
    def exec_raw(
        self, argv: Sequence[str], *, timeout: float | None = None, input: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Run an argv inside the container (no shell interpretation)."""
        return self._runtime(["exec", self.name, *argv], timeout=timeout, input=input)

    def run(
        self, command: str | Sequence[str], *, timeout: float | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Run a command inside kalibox.

        A string is executed via ``bash -lc`` (pipes/globs work); a list is run
        as a literal argv (no shell, injection-safe for target-derived data).
        """
        argv = ["bash", "-lc", command] if isinstance(command, str) else list(command)
        return self.exec_raw(argv, timeout=timeout)

    # ----------------------------------------------------------- file transfer
    def cp_out(self, container_path: str, host_path: str) -> subprocess.CompletedProcess[str]:
        """Copy a file out of the container to the host."""
        return self._runtime(["cp", f"{self.name}:{container_path}", host_path])

    def cp_in(self, host_path: str, container_path: str) -> subprocess.CompletedProcess[str]:
        """Copy a host file into the container."""
        return self._runtime(["cp", host_path, f"{self.name}:{container_path}"])


_USAGE = """kalibox — run offensive tooling inside an isolated Kali container

Usage:
  kalibox up                 Provision + start the container (first run pulls + installs)
  kalibox status             Show container state
  kalibox <command...>       Run a command inside kalibox (e.g. kalibox nmap -sCV 10.129.33.77)
  kalibox shell              Open an interactive Kali shell
  kalibox down               Stop the container
  kalibox destroy            Remove the container

All attacks run inside the container with host networking; the host is never
asked for root.
"""


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the ``kalibox`` console script."""
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    box = KaliBox()

    if not args or args[0] in ("-h", "--help", "help"):
        sys.stdout.write(_USAGE)
        return 0

    sub = args[0]
    try:
        if sub == "up":
            box.ensure()
            sys.stdout.write(f"[kalibox] up: {box.name} ({box.image}), workdir {box.workdir}\n")
            return 0
        if sub == "status":
            for k, v in box.status().items():
                sys.stdout.write(f"  {k}: {v}\n")
            return 0
        if sub == "down":
            box.stop()
            sys.stdout.write(f"[kalibox] stopped: {box.name}\n")
            return 0
        if sub == "destroy":
            box.destroy()
            sys.stdout.write(f"[kalibox] destroyed: {box.name}\n")
            return 0
        if sub == "shell":
            box.start()
            os.execvp(box.runtime, [box.runtime, "exec", "-it", box.name, "bash"])

        # Default: run the whole argv as a command inside the container.
        box.ensure(provision=True)
        result = box.run(args)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode
    except KaliBox.DockerNotFoundError as e:
        sys.stderr.write(f"[kalibox] {e}\n")
        return 127


if __name__ == "__main__":
    raise SystemExit(main())
