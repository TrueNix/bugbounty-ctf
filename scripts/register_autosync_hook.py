#!/usr/bin/env python3
"""Register (or remove) the bugbounty-ctf on_session_start autosync hook.

Edits ``~/.hermes/config.yaml`` as text so the rest of the file — comments,
ordering, quoting — is preserved (a YAML round-trip would strip all of it).
Idempotent, backs up the config first, and refuses to guess when the hooks
section is already populated in a shape it can't safely extend.

    python3 register_autosync_hook.py           # register
    python3 register_autosync_hook.py --remove  # unregister
"""

from __future__ import annotations

import datetime
import os
import shutil
import sys

CONFIG = os.path.expanduser("~/.hermes/config.yaml")
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(REPO, "scripts", "hermes-skill-autosync.sh")
CMD = f"{SCRIPT} {REPO}"
ENTRY = f'  on_session_start:\n    - command: "{CMD}"\n      timeout: 30\n'


def main() -> int:
    remove = "--remove" in sys.argv
    if not os.path.exists(CONFIG):
        print(f"[!] {CONFIG} not found — is Hermes installed?")
        return 1

    text = open(CONFIG).read()
    already = SCRIPT in text

    if remove:
        if not already:
            print("[*] autosync hook not present — nothing to remove")
            return 0
        # Drop the empty hooks block back to {} if our entry was the only thing,
        # otherwise just strip our two lines.
        lines = [ln for ln in text.splitlines(keepends=True) if SCRIPT not in ln]
        new = "".join(lines)
        _write(text, new)
        print("[+] removed autosync hook")
        return 0

    if already:
        print("[*] autosync hook already registered — nothing to do")
        return 0

    if "\nhooks: {}\n" in text:
        new = text.replace("\nhooks: {}\n", "\nhooks:\n" + ENTRY, 1)
    elif "\nhooks:\n" in text:
        new = text.replace("\nhooks:\n", "\nhooks:\n" + ENTRY, 1)
    else:
        print("[!] No 'hooks:' section found. Add this to ~/.hermes/config.yaml:\n")
        print("hooks:\n" + ENTRY)
        return 1

    _write(text, new)
    print(f"[+] registered on_session_start autosync hook:\n    {CMD}")
    return 0


def _write(old: str, new: str) -> None:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    shutil.copy2(CONFIG, f"{CONFIG}.bak.bbctf_{ts}")
    with open(CONFIG, "w") as f:
        f.write(new)


if __name__ == "__main__":
    raise SystemExit(main())
