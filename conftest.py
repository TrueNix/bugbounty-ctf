"""Ensure pytest imports the in-repo package, not an installed copy.

A Hermes skill install of this project can sit ahead of the working tree on
PYTHONPATH and silently shadow it, so tests would run against stale code. Pin
the repo's ``src`` to the front of sys.path before collection.
"""

import os
import sys

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if _SRC in sys.path:
    sys.path.remove(_SRC)
sys.path.insert(0, _SRC)

# Drop any already-imported copy so the repo version is the one loaded.
for _mod in [
    m for m in list(sys.modules) if m == "bugbounty_ctf" or m.startswith("bugbounty_ctf.")
]:
    del sys.modules[_mod]
