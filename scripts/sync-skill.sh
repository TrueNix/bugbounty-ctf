#!/usr/bin/env bash
# Mirror the skill-relevant files from the repo into a Hermes skill directory
# (copy mode). Idempotent. Used by `./install.sh --copy`, `make sync-skill`, and
# the post-commit drift-protection hook.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_DIR="${1:-${HERMES_SKILL_DIR:-$HOME/.hermes/skills/red-teaming/bugbounty-ctf}}"

mkdir -p "$SKILL_DIR/src"

# Replace tracked skill assets (never tests/.git/caches).
rm -rf "$SKILL_DIR/src/bugbounty_ctf" "$SKILL_DIR/references" "$SKILL_DIR/templates"
cp -R "$REPO_DIR/src/bugbounty_ctf" "$SKILL_DIR/src/bugbounty_ctf"
cp -R "$REPO_DIR/references" "$SKILL_DIR/references"
cp -R "$REPO_DIR/templates" "$SKILL_DIR/templates"
cp "$REPO_DIR/SKILL.md" "$REPO_DIR/README.md" "$REPO_DIR/pyproject.toml" "$SKILL_DIR/"

find "$SKILL_DIR" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
echo "[+] Synced skill → $SKILL_DIR"
