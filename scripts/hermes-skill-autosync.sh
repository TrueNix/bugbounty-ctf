#!/usr/bin/env bash
# Hermes on_session_start hook — keep the bugbounty-ctf skill current with GitHub.
#
# Safe by design:
#   - only fast-forwards a CLEAN checkout that is on `main`
#   - throttled (won't hit the network more than once per BBCTF_AUTOSYNC_THROTTLE)
#   - never fails the session: always exits 0
#
# Shell hooks run with shell=False, so the repo path is passed as an argument
# (baked in at install time) rather than via an env-var prefix.
#
#   Usage: hermes-skill-autosync.sh <repo_dir>
set -uo pipefail

REPO="${1:-}"
[ -n "$REPO" ] && [ -d "$REPO/.git" ] || exit 0
SKILL="${HERMES_SKILL_DIR:-$HOME/.hermes/skills/red-teaming/bugbounty-ctf}"
STAMP="$REPO/.git/.bbctf-autosync"
THROTTLE_SECS="${BBCTF_AUTOSYNC_THROTTLE:-3600}"

# Throttle: skip if we already checked within the window.
if [ -f "$STAMP" ]; then
    now="$(date +%s)"
    last="$(date -r "$STAMP" +%s 2>/dev/null || echo 0)"
    [ $((now - last)) -lt "$THROTTLE_SECS" ] && exit 0
fi
touch "$STAMP" 2>/dev/null || true

cd "$REPO" 2>/dev/null || exit 0

# Stay out of the way unless this is a clean checkout on main.
[ -n "$(git status --porcelain 2>/dev/null)" ] && exit 0
[ "$(git rev-parse --abbrev-ref HEAD 2>/dev/null)" = "main" ] || exit 0

git fetch --quiet origin main 2>/dev/null || exit 0
local_rev="$(git rev-parse HEAD 2>/dev/null || echo x)"
remote_rev="$(git rev-parse origin/main 2>/dev/null || echo y)"
[ "$local_rev" = "$remote_rev" ] && exit 0   # already current

git merge --ff-only --quiet origin/main 2>/dev/null || exit 0
echo "[bbctf] skill updated ${local_rev:0:7} -> ${remote_rev:0:7}" >&2

# Mirror into the skill dir if it is a copy (a symlink reflects the repo already).
[ -L "$SKILL" ] || bash "$REPO/scripts/sync-skill.sh" "$SKILL" >/dev/null 2>&1 || true
exit 0
