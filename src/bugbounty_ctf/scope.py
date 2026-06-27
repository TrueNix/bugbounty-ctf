"""Scope enforcement — keep requests on authorized targets.

Bug-bounty programs scope testing to specific hosts; sending payloads to an
out-of-scope host is both useless and a policy violation. A ``ScopeGuard`` is
consulted by ``SecurityScanner`` before every request and hard-stops anything
outside the allowlist by raising :class:`OutOfScopeError`.

Usage:
    from bugbounty_ctf.scope import ScopeGuard
    from bugbounty_ctf import SecurityScanner

    scope = ScopeGuard(["*.example.com", "api.example.org"])
    scanner = SecurityScanner("https://app.example.com/", scope=scope)
    # Any request to a host outside the allowlist raises OutOfScopeError.
"""

from __future__ import annotations

from urllib.parse import urlparse


class OutOfScopeError(RuntimeError):
    """Raised when a request targets a host outside the configured scope."""

    def __init__(self, host: str) -> None:
        super().__init__(f"Out of scope: {host!r} is not in the allowlist")
        self.host = host


class ScopeGuard:
    """Allowlist of authorized hosts for testing.

    Each allowed entry is one of:
      - an exact host:           ``api.example.com``
      - a wildcard label:        ``*.example.com``  (matches any subdomain)
      - a bare apex with ``allow_subdomains=True`` (the default), in which case
        ``example.com`` also matches ``*.example.com``.

    Matching is case-insensitive and port-insensitive. An empty allowlist
    denies everything (fail-closed), which is the safe default for a guard.
    """

    def __init__(self, allowed: list[str] | None = None, *, allow_subdomains: bool = True) -> None:
        self.allow_subdomains = allow_subdomains
        self._exact: set[str] = set()
        self._wildcard_suffixes: set[str] = set()
        for entry in allowed or []:
            self.add(entry)

    def add(self, entry: str) -> None:
        """Add a host or ``*.host`` pattern to the allowlist."""
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            return
        # Accept full URLs too, for convenience.
        if "://" in entry:
            entry = urlparse(entry).hostname or ""
        if entry.startswith("*."):
            self._wildcard_suffixes.add(entry[2:])
        else:
            self._exact.add(entry)

    def is_allowed(self, url_or_host: str) -> bool:
        """Return True if the URL or host is within scope."""
        host = url_or_host
        if "://" in host:
            host = urlparse(host).hostname or ""
        host = host.split("@")[-1].split(":")[0].strip().lower().rstrip(".")
        if not host:
            return False

        if host in self._exact:
            return True
        for suffix in self._wildcard_suffixes:
            if host == suffix or host.endswith(f".{suffix}"):
                return True
        if self.allow_subdomains:
            for apex in self._exact:
                if host.endswith(f".{apex}"):
                    return True
        return False

    def check(self, url: str) -> None:
        """Raise :class:`OutOfScopeError` if ``url`` is out of scope."""
        if not self.is_allowed(url):
            host = urlparse(url).hostname or url
            raise OutOfScopeError(host)
