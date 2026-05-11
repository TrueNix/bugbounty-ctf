# Bug Bounty & CTF Skill

Hermes Agent skill for Capture The Flag challenges and authorized bug bounty hunting.

**Philosophy: Discover, Don't Read.** Black-box testing methodology — find vulnerabilities through observation and systematic testing, not by reading source code.

## What's Inside

### Core Scripts
- **`scripts/security_engine.py`** — Systematic payload testing engine with response diffing, attack surface mapping, and state persistence
- **`scripts/quick_test.py`** — One-liner test functions for SQLi, SSTI, CMDi, LFI, NoSQLi, LDAP, SSRF
- **`scripts/advanced_tests.py`** — WAF/defense detection, race conditions, XXE, deserialization, JWT attacks, file upload bypass, chain exploitation, structured reporting

### Reference Files
- **`references/payload-library.md`** — Organized payload sets by vulnerability class with filter bypass variants
- **`references/escalate-ctf-walkthrough.md`** — Full SQLi → webshell → SUID → docker root chain
- **`references/aclabs-platform-patterns.md`** — ACLabs.pro patterns and methodology

### Templates
- **`templates/exploit_template.py`** — Pwntools exploit skeleton
- **`templates/bug-bounty-report.md`** — Report template for bounty submissions

## Quick Start

```python
exec(open("scripts/security_engine.py").read())
exec(open("scripts/quick_test.py").read())
exec(open("scripts/advanced_tests.py").read())

# Test in one line
test_login_sqli("http://target/login")
test_race_condition("http://target/redeem", data={"code": "X"}, workers=30)
map_surface("http://target/")

# Full scan with report
scanner = SecurityScanner("http://target/")
save_report(scanner)
```

## Features

| Capability | Function |
|:-----------|:---------|
| Payload testing | `run_payload_set()` with baseline comparison |
| Response diff | Status, length, timing, content patterns |
| Attack surface map | `map_surface()` — forms, links, tech |
| WAF detection | `detect_defenses()` — WAF, rate limits, filters |
| SQL injection | `test_login_sqli()` |
| SSTI | `test_ssti()` |
| Command injection | `test_command_injection()` |
| Path traversal | `test_path_traversal()` |
| NoSQL injection | `test_nosqli()` |
| LDAP injection | `test_ldap_injection()` |
| SSRF | `test_ssrf()` |
| XXE | `test_xxe()` |
| Race conditions | `test_race_condition()` |
| Deserialization | `test_pickle_deserialization()` / `test_yaml_deserialization()` |
| JWT attacks | `test_jwt_attacks()` — alg=none, weak secret bruteforce |
| File upload | `test_file_upload()` — 9 bypass variants |
| Chain exploitation | `ChainContext` — carry tokens across exploits |
| Reporting | `generate_report()` / `save_report()` |

## Security

This tool is for authorized security testing only.

## License

MIT
