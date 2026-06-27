#!/usr/bin/env bash
# Install bugbounty-ctf as an importable Python package AND a Hermes skill.
#
# Usage:
#   ./install.sh            # editable pip install + symlink the skill (stays in sync)
#   ./install.sh --copy     # copy files instead (+ post-commit re-sync hook, drift-proof)
#   HERMES_SKILL_DIR=/path ./install.sh   # override the skill location
#
# A bare `git clone` only gives Hermes the SKILL.md / references methodology;
# `from bugbounty_ctf import ...` needs the package installed, which this does.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="${HERMES_SKILL_DIR:-$HOME/.hermes/skills/red-teaming/bugbounty-ctf}"
MODE="symlink"
AUTOSYNC=0
for arg in "$@"; do
    case "$arg" in
        --copy) MODE="copy" ;;
        --autosync) AUTOSYNC=1 ;;
    esac
done

echo "[*] repo:  $REPO_DIR"
echo "[*] skill: $SKILL_DIR ($MODE mode)"

echo "[*] Installing Python package (editable; bundled wordlists ship as package data)..."
pip install -e "$REPO_DIR"

mkdir -p "$(dirname "$SKILL_DIR")"

if [ "$MODE" = "symlink" ]; then
    if [ -L "$SKILL_DIR" ]; then
        rm "$SKILL_DIR"
    elif [ -e "$SKILL_DIR" ]; then
        echo "[!] $SKILL_DIR exists and is not a symlink."
        echo "    Remove/back it up, or run with --copy. (HERMES_SKILL_DIR overrides the path.)"
        exit 1
    fi
    ln -s "$REPO_DIR" "$SKILL_DIR"
    echo "[+] Symlinked — the installed skill stays in sync with the repo automatically."
else
    bash "$REPO_DIR/scripts/sync-skill.sh" "$SKILL_DIR"
    # Drift protection: re-sync the copy after every commit.
    hook="$REPO_DIR/.git/hooks/post-commit"
    if [ -d "$REPO_DIR/.git" ]; then
        {
            echo "#!/usr/bin/env bash"
            echo "exec bash \"$REPO_DIR/scripts/sync-skill.sh\" \"$SKILL_DIR\""
        } >"$hook"
        chmod +x "$hook"
        echo "[+] Copied + installed a post-commit re-sync hook (keeps the copy drift-free)."
    fi
fi

if [ "$AUTOSYNC" = "1" ]; then
    echo "[*] Registering on_session_start autosync hook (pull latest from GitHub on start)..."
    python3 "$REPO_DIR/scripts/register_autosync_hook.py"
    echo "    Note: Hermes asks for one-time consent the first time the hook fires."
fi

python -c "from bugbounty_ctf import SecurityScanner; print('[+] import OK')"
echo "[+] Done."
