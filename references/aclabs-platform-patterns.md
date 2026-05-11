# ACLabs.pro Platform Patterns

ACLabs.pro is a Russian-language CTF platform using 10.10.10.0/24 lab IPs.

## Challenge Structure (from writeup analysis)

ACLabs challenges follow multi-stage escalation patterns with 3-5 flags:

```
Recon → Web Vuln → Container Root (Flag 1)
  → Lateral Movement (Flag 2)
  → Privilege Escalation (Flag 3-N)
  → Host Escape (Final Flag)
```

### Flag Naming Patterns
- `flag1.txt`, `flag2.txt`, etc. in user home directories
- `flag_{md5_hash}` format (e.g., `flag_73b93510202e14edfc2d07087c2052d4`)
- `/flag`, `/root/flag`, `/root/root`, `/user.txt`
- Sometimes `flag1`, `flag2`, etc. without extension

### Common Challenge Patterns (from completed writeups)

| Challenge | IP | Vulns | Stages |
|-----------|-----|-------|--------|
| Dragon | 10.10.10.57 | SSTI→SQLi, FILE priv | Web→DB→SSH→Sudo(mawk)→Root |
| PigeonsRevenge | 10.10.10.215 | Port knocking, Webmin CVE-2019-15107 | Video metadata→knocking→Webmin RCE→Ligolo pivot→SUID bypass |
| Pwnelines | 10.10.10.x | Subdomain fuzzing, Jenkins ACL bypass | Nginx→jenk subdomain→Jenkins RCE→Container flag |
| SaveWalterWhite | 10.10.10.x | Path traversal, RFI | Apache→LFI→RFI→RCE→sudo backup→Borg→SUID→Docker escape |

## Recon Approach

1. **Check the writeup repo** first: `github.com/alfabuster/Aclabs-pro-Writeups`
   - Contains detailed writeups for Dragon, PigeonsRevenge, Pwnelines, SaveWalterWhite
   - Shows MITRE ATT&CK mapping, CVSS scoring, exact commands used
   - Pattern: each challenge has its own directory with `_writeup.md` file

2. **Common ports**: 22 (SSH), 80 (HTTP nginx/Apache), sometimes unusual services
3. **Web enumeration**: Subdomain fuzzing is often required (standard wordlists miss them)
4. **Video/image metadata**: `exiftool` often reveals hidden clues (port knocking sequences)

## Vulnerability Patterns

### Web Layer
- **SSTI → SQLi**: Testing `{{7*7}}` reveals injection points
- **Path Traversal → RFI**: `image.php?file=` style endpoints
- **Subdomain discovery**: Non-obvious subdomains not in standard DNS wordlists
- **Port knocking**: Hidden in video metadata, use `nmap -Pn -p 2,8,10 IP`

### Escalation Layer
- **Docker containers**: Initial access usually lands in a container
- **Container escape**: Ligolo-ng pivot, privileged container escape, Docker socket access
- **Sudo abuse**: World-writable scripts, SUID binaries with filter bypasses
- **Credential discovery**: Database credentials in source code, SSH key cracking

### Final Layer
- **Docker host escape**: Privileged containers can mount host filesystem
- **SUID exploitation**: Custom binaries requiring OSINT/filter bypass
- **Sudo to root**: `tee`, `mawk`, and other GTFOBins patterns

## Dynamically Generated Labs (AgenticVerse/PwnlyFence)

ACLabs also hosts dynamically generated multi-challenge labs with 30+ vulnerability modules:

### Source Code Location
```
/home/truenix/aclabs/lab/agenticverse_entities/{hash}/_lab/src/vulnerabilities/
```

### Architecture
- **31 codenames** (alpha through zulu), each a separate Flask blueprint
- **Step categories**: Foothold (1) → Escalation (2) → Impact (3) → Credential Access (5)
- **Session tracking**: `GET /session/progress` returns completed steps
- **Each challenge** has `canonical_exploit()` showing the exact intended payload
- **Variations**: Each codename can have multiple difficulty tiers (default, blind, hard, etc.)

### Exploitation Pattern
1. Read `canonical_exploit()` from source to find exact payload
2. Check `mark_exploited()` to understand success conditions
3. Some variations require WSGI `environ_overrides` — not HTTP-exploitable
4. Session progress at `/session/progress` tracks completion

See `references/aclabs-source-exploitation.md` for the full methodology.

## Answer Submission

ACLabs uses a web platform (behind Cloudflare) where you submit answers after
solving. The platform shows "Вы можете оценить задание только после решения
всех флагов" (You can only evaluate the task after solving all flags).

For identification-only challenges (like Marketplace), the answer is the
vulnerability type or description submitted via the platform UI.
