# Bug Bounty & CTF Toolkit

A Python toolkit for CTF challenges and authorized bug bounty hunting. Black-box
testing methodology — discover vulnerabilities through observation and systematic
testing, not by reading source code.

**Philosophy: Discover, Don't Read.**

Covers web exploitation, cryptography, binary exploitation (pwn), reverse
engineering, forensics, OSINT, AWS exploitation, SSRF pivoting, an FTS5-backed
knowledge base, and a multi-agent orchestrator that can drive Hermes sub-agents.

## Installation

```bash
pip install bugbounty-ctf

# Optional: for binary exploitation
pip install bugbounty-ctf[pwn]

# Development
pip install -e ".[dev]"
```

Bundled SecLists payload wordlists ship inside the package
(`bugbounty_ctf/wordlists/`), so they are available offline after install — no
download required.

### Use as a Hermes skill

A bare `git clone` only gives Hermes the methodology layer (`SKILL.md`,
`references/`, `templates/`). The Python toolkit
(`from bugbounty_ctf import ...`) must be installed to be importable. Use the
installer:

```bash
git clone https://github.com/TrueNix/bugbounty-ctf \
    ~/.hermes/skills/red-teaming/bugbounty-ctf
cd ~/.hermes/skills/red-teaming/bugbounty-ctf
./install.sh            # editable pip install + register the skill (symlink, stays in sync)
```

- **Default (symlink)** — the skill directory points at the repo, so it never
  drifts from your working copy.
- **`./install.sh --copy`** — copies files into the skill directory instead and
  installs a git `post-commit` hook that re-mirrors them, so the copy stays
  drift-free too. `make sync-skill` re-mirrors on demand.
- `HERMES_SKILL_DIR=/path ./install.sh` overrides the skill location.

**Auto-update from GitHub on start.** Add `--autosync` (or `make install-autosync`)
to register a Hermes `on_session_start` hook that pulls the latest `main` from
GitHub when a session begins:

```bash
./install.sh --autosync
```

The hook (`scripts/hermes-skill-autosync.sh`) is safe by design: it only
fast-forwards a **clean checkout on `main`**, is throttled (one network check
per hour, tunable via `BBCTF_AUTOSYNC_THROTTLE`), and never blocks the session
(always exits 0). Hermes asks for one-time consent the first time it fires.
Remove it with `python3 scripts/register_autosync_hook.py --remove`.

`make check` runs the full gate (ruff + mypy strict + pytest).

## Quick Start

```python
from bugbounty_ctf import SecurityScanner, ScopeGuard
from bugbounty_ctf.api import test_login_sqli, test_xss, map_surface, save_report

# Keep testing on authorized hosts — out-of-scope requests hard-fail.
scope = ScopeGuard(["*.example.com"])
scanner = SecurityScanner("http://app.example.com/", scope=scope)

surface = map_surface("http://app.example.com/", scanner=scanner)
test_login_sqli("http://app.example.com/login", scanner=scanner)
test_xss("http://app.example.com/search", param_name="q", scanner=scanner)
save_report(scanner)
```

## Web Exploitation

| Capability | Function |
|:-----------|:---------|
| Payload testing | `SecurityScanner.run_payload_set()` with baseline comparison |
| Response diff | Status, length, timing, content patterns (noise-stripped) |
| Attack surface map | `map_surface()` — forms (any attribute order), links, tech |
| WAF / defense detection | `detect_defenses()` — WAF, rate limits, filters, missing headers |
| SQL injection | `test_login_sqli()` |
| SSTI | `test_ssti()` — confirms via baseline comparison, 8 engines |
| Command injection | `test_command_injection()` |
| Path traversal | `test_path_traversal()` |
| NoSQL injection | `test_nosqli()` |
| LDAP injection | `test_ldap_injection()` |
| SSRF | `test_ssrf()` + IP-encoding bypasses, AWS metadata enumeration |
| XSS | `test_xss()` — filter-bypass escalation ladder |
| IDOR | `test_idor()` — sequential ID probing with diff detection |
| XXE | `test_xxe()` |
| Blind / OOB (OAST) | `OASTServer` + `test_blind_ssrf()` / `test_blind_rce()` / `test_blind_xxe()` — confirm blind vulns via callback |
| CORS misconfig | `test_cors()` — origin reflection, `null` trust, credentialed wildcard |
| Open redirect | `test_open_redirect()` — redirect params + bypass payloads |
| Content discovery | `discover_content()` — bundled `dirbrute` list, catch-all filtering |
| Race conditions | `test_race_condition()` — concurrent request testing |
| Deserialization | `test_pickle_deserialization()` / `test_yaml_deserialization()` |
| JWT attacks | `test_jwt_attacks()`, `decode_jwt()`, `forge_jwt_alg_none/hs256()` |
| File upload | `test_file_upload()` — bypass variants + RCE verification |
| GraphQL | `test_graphql_alias_batch()`, `graphql_introspection()` |
| Request smuggling | `SmugglingDetector` — CL.TE / TE.CL / TE.TE (raw-socket) |
| WebSockets | `WebSocketTester` |
| Chain exploitation | `ChainContext` — carry tokens/creds across exploits |
| Reporting | `generate_report()` / `save_report()` — markdown or JSON |
| Scope enforcement | `ScopeGuard` — fail-closed host allowlist on every request |

## Other Domains

| Domain | Entry point |
|:-------|:------------|
| Cryptography | `CryptoToolkit` — RSA (small-e, common-modulus, Wiener, Fermat), XOR, hash crack, encoding chains |
| Binary exploitation | `PwnToolkit` — checksec, cyclic offset, ROP helpers (needs `pwntools`) |
| Reverse engineering | `ReverseToolkit` — strings/symbols, radare2, Ghidra headless |
| Forensics | `ForensicsToolkit` — binwalk, exiftool, steghide, zsteg, volatility |
| OSINT | `OSINTToolkit` — crt.sh subdomains, dorks, Wayback, DNS, subdomain takeover |
| AWS exploitation | `AWSExploiter`, `exploit_aws_credentials()`, SigV4 presigned URLs |
| SSRF pivoting | `SSRFPivot` — internal port scan / service discovery via SSRF |
| Post-exploitation | `PostExploit`, `post_exploit_enum()`, SUID PTY extraction |
| Flag hunting | `FlagHunter`, `hunt_flags()` |
| NFS enumeration | `NFSEnumerator` — exports, parent/sibling mounts, SSH-key/secret + UID-spoof scan |
| Mail enumeration | `MailEnumerator` — IMAP login/spray (concurrent), mailbox secret harvest |
| Payload wordlists | `WordlistLoader` — bundled SecLists lists + offline fallbacks |

## Knowledge Base & Second Brain

The toolkit accumulates knowledge across runs rather than starting cold:

- **`KnowledgeBase`** — FTS5 full-text search over the `references/` methodology
  docs; `search()` and `suggest_methodology(tech_hints)` retrieve relevant
  exploit paths.
- **Recall** — `ScannerDB` persists findings/history/attack-surface per host
  (de-duplicated). The orchestrator recalls prior findings for a host into new
  sessions (`findings_for_host()`).
- **Write-back** — confirmed findings are written back as searchable
  `learned::` lessons (`KnowledgeBase.add_lesson()`) that survive `reindex()`,
  so future runs benefit from what actually worked.

## Multi-Agent Orchestration

`SkillOrchestrator` drives a recon → research → fuzz → exploit → verify workflow:

```python
from bugbounty_ctf.skill_runner import SkillOrchestrator

runner = SkillOrchestrator("http://target/")

# Interactive: the running agent executes each phase's guidance itself.
guidance = runner.get_recon_guidance()   # includes RAG context + prior memory

# Autonomous (headless): spawn one Hermes sub-agent (`hermes -z`) per phase.
final = runner.run_with_agents()          # lazy guidance, shared state, verification
print(final["confirmed_findings"], final["refuted_findings"])
```

- **Lazy guidance** — each phase is built from current scanner state, so findings
  feed forward.
- **Structured output** — sub-agents emit a `<FINDINGS>` JSON block that the
  orchestrator parses and merges (deduped); they also share the orchestrator's
  state file + `ScannerDB`.
- **Adversarial verification** — a panel of skeptic sub-agents tries to refute
  each finding; majority-refuted findings are dropped.

`Orchestrator` (non-agent) and the `agents` module (`ReconAgent`, `FuzzAgent`,
`ExploitAgent`, …) provide an in-process alternative.

## Architecture

```
bugbounty_ctf/
├── engine.py            # SecurityScanner, ScannerDB, ResponseDiff, IP/SSRF utils
├── scope.py             # ScopeGuard — authorized-host enforcement
├── quick_tests.py       # One-liner tests: SQLi, SSTI, CMDi, SSRF, CORS, redirect, discovery
├── advanced_tests.py    # WAF/defense detection, race, XXE, JWT, XSS, IDOR, GraphQL, AWS presign
├── web_recon.py         # Automated web recon (shell-injection-safe)
├── crypto.py            # RSA / XOR / hash / encoding attacks
├── pwn.py               # Binary exploitation (pwntools)
├── reverse.py           # radare2 / Ghidra reverse engineering
├── forensics.py         # binwalk / exiftool / steghide / volatility
├── osint.py             # subdomains, dorks, Wayback, subdomain takeover
├── nfs_enum.py          # NFS exports, deeper/sibling mounts, sensitive-file + UID-spoof scan
├── mail_enum.py         # IMAP user-enum, concurrent spray, mailbox secret harvest
├── aws_exploit.py       # AWS credential abuse, SigV4 presigned URLs
├── ssrf_pivot.py        # SSRF-based internal network pivoting
├── smuggling.py         # HTTP request smuggling (raw socket)
├── websocket.py         # WebSocket testing
├── post_exploit.py      # Privesc enumeration
├── alpine_pty_extract.py# SUID file extraction via PTY
├── oast.py              # In-process OAST collaborator + blind SSRF/RCE/XXE tests
├── callback_listener.py # Standalone CLI HTTP listener for XSS/SSRF callbacks
├── flag_hunter.py       # Filesystem flag hunting
├── knowledge.py         # FTS5 knowledge base + learned lessons (write-back)
├── orchestrator.py      # In-process phase orchestrator
├── skill_runner.py      # Hermes sub-agent orchestrator (recall + verify + write-back)
├── agents.py            # Recon/Research/Fuzz/Exploit agents
├── hypothesis.py        # Hypothesis-driven testing engine
├── observations.py      # Observation store + next-test recommendation
├── session_recorder.py  # Record/replay HTTP sessions
├── failures.py          # Structured request-failure handling
├── wordlists.py         # WordlistLoader (bundled SecLists + cache)
└── api.py               # Public API exports
```

## Reference Library

The `references/` directory contains methodology docs built from real CTF and bug
bounty experience (SQLi playbooks, privilege-escalation chains, nginx-ui
exploitation, HTB/ACLabs recon, payload library, and `ctf_helper.py`). They are
indexed into the knowledge base and searchable via `KnowledgeBase.search()`.

## Templates

- **`templates/exploit_template.py`** — Pwntools exploit skeleton
- **`templates/bug-bounty-report.md`** — Report template for bounty submissions

## Testing

```bash
pytest --cov=bugbounty_ctf --cov-report=term-missing
```

Tests use the `responses` library and mocks — no real network calls. The suite is
linted with `ruff` and type-checked with `mypy --strict`.

## Security

This toolkit is for authorized security testing only. Always obtain explicit
permission before testing any target, and use `ScopeGuard` to enforce your
authorized scope. See [SECURITY.md](SECURITY.md) for reporting vulnerabilities in
this project.

## License

MIT
