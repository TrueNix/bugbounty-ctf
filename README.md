# Bug Bounty & CTF Toolkit

A Python toolkit for CTF challenges and authorized bug bounty hunting. Black-box testing methodology — discover vulnerabilities through observation and systematic testing, not by reading source code.

**Philosophy: Discover, Don't Read.**

## Installation

```bash
pip install bugbounty-ctf

# Optional: for binary exploitation
pip install bugbounty-ctf[pwn]

# Development
pip install -e ".[dev]"
```

## Quick Start

```python
from bugbounty_ctf import SecurityScanner
from bugbounty_ctf.api import test_login_sqli, test_xss, map_surface, save_report

# Map attack surface
scanner = SecurityScanner("http://target/")
surface = map_surface("http://target/")

# Test a login form for SQLi
test_login_sqli("http://target/login", scanner=scanner)

# Test for XSS with filter-bypass escalation
test_xss("http://target/search", param_name="q", scanner=scanner)

# Generate and save a report
save_report(scanner)
```

## Features

| Capability | Function |
|:-----------|:---------|
| Payload testing | `run_payload_set()` with baseline comparison |
| Response diff | Status, length, timing, content patterns |
| Attack surface map | `map_surface()` — forms (any attribute order), links, tech |
| WAF detection | `detect_defenses()` — WAF, rate limits, filters, missing headers |
| SQL injection | `test_login_sqli()` |
| SSTI | `test_ssti()` — confirms via baseline comparison |
| Command injection | `test_command_injection()` |
| Path traversal | `test_path_traversal()` |
| NoSQL injection | `test_nosqli()` |
| LDAP injection | `test_ldap_injection()` |
| SSRF | `test_ssrf()` |
| XSS | `test_xss()` — 8-level filter-bypass escalation ladder |
| IDOR | `test_idor()` — sequential ID probing with diff detection |
| XXE | `test_xxe()` |
| Race conditions | `test_race_condition()` — concurrent request testing |
| Deserialization | `test_pickle_deserialization()` / `test_yaml_deserialization()` |
| JWT attacks | `test_jwt_attacks()` — alg=none, weak HS256 secret bruteforce |
| File upload | `test_file_upload()` — 9 bypass variants + RCE verification |
| GraphQL | `test_graphql_alias_batch()` — alias-batch brute force |
| Chain exploitation | `ChainContext` — carry tokens across exploits |
| Reporting | `generate_report()` / `save_report()` — markdown or JSON |

## Architecture

```
bugbounty_ctf/
├── engine.py              # SecurityScanner, ResponseDiff, derive_base_url
├── quick_tests.py         # One-liner test functions (SQLi, SSTI, CMDi, etc.)
├── advanced_tests.py     # WAF detection, race conditions, XXE, JWT, XSS, IDOR, GraphQL
├── web_recon.py           # Automated web target recon (shell-injection-safe)
├── callback_listener.py   # HTTP listener for XSS/SSRF callback detection
├── alpine_pty_extract.py  # SUID binary file extraction via PTY
└── api.py                 # Public API exports
```

## Reference Library

The `references/` directory contains methodology docs built from real CTF and bug bounty experience:

| File | Use when |
|:-----|:---------|
| `payload-library.md` | Organized payload sets by vulnerability class |
| `escalate-ctf-walkthrough.md` | SQLi → webshell → SUID → docker root chain |
| `advanced-escalation.md` | SUID PTY, PAM scripts, Docker escapes |
| `suid-webshell-exploitation.md` | SUID binaries via webshell |
| `suid-sg-docker-escalation.md` | `setresuid()` + `sg docker` pattern |
| `docker-privilege-escalation.md` | Docker group → root |
| `curl-executor-webshell.md` | SSRF curl executor → webshell → RCE |
| `sqlite-php-sqli-playbook.md` | PHP+SQLite SQLi attack tree |
| `sqlite-sqli-deep-dive.md` | pragma_*, sqlite_dbpage, FTS3 tokenizer |
| `htb-recon-methodology.md` | HTB recon: machine ID, GitHub source discovery |
| `aclabs-platform-patterns.md` | ACLabs.pro patterns, vuln-ID vs flag-capture |
| `aclabs-drtbp-architecture.md` | DRTBP challenge architecture |
| `aclabs-source-exploitation.md` | ACLabs source exploitation methodology |
| `nginx-ui-exploitation.md` | nginx-ui: unauthenticated backup, RSA login |
| `nginx-ui-login-encryption.md` | nginx-ui RSA login workflow |
| `nginx-ui-backdoor.md` | nginx-ui backdoor analysis |
| `recreating-ctf-labs-locally.md` | Rebuild CTF target as Docker Compose |
| `ctf_helper.py` | `analyze_challenge()`, encoding detection, XOR, hash cracking |

## Templates

- **`templates/exploit_template.py`** — Pwntools exploit skeleton
- **`templates/bug-bounty-report.md`** — Report template for bounty submissions

## Testing

```bash
pytest --cov=bugbounty_ctf --cov-report=term-missing
```

Tests use the `responses` library for mocked HTTP — no real network calls.

## Security

This toolkit is for authorized security testing only. Always obtain explicit
permission before testing any target. See [SECURITY.md](SECURITY.md) for reporting
vulnerabilities in this project.

## License

MIT