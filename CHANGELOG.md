# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added
- **OAST out-of-band detection** — `OASTServer` in-process collaborator plus
  `test_blind_ssrf` / `test_blind_rce` / `test_blind_xxe` to confirm blind
  vulnerabilities via callback.
- **Second-brain memory loop** — cross-run recall of prior findings,
  hypotheses, and observations into orchestrator guidance; write-back of
  confirmed findings as searchable `learned::` lessons; durable
  observation/hypothesis persistence; finding dedup; history retention
  (`prune_history`); finding provenance (`source`); optional embedding-based
  hybrid search (`KnowledgeBase(embedder=...)`).
- **Hermes sub-agent workflow** — `SkillOrchestrator.run_with_agents` with lazy
  per-phase guidance, a shared-state bootstrap, a `<FINDINGS>` structured-output
  contract, and an adversarial verification pass.
- **New web/recon capabilities** — `test_cors`, `test_open_redirect`,
  `discover_content` (bundled `dirbrute`), `OSINTToolkit.check_subdomain_takeover`,
  and a fail-closed `ScopeGuard`.
- **RSA Fermat factorization** — `CryptoToolkit.rsa_fermat(n, e, c)` factors a
  modulus whose primes are close together, derives `d`, and decrypts `c`
  (fills the gap advertised in the RSA decision tree). `ScopeGuard` now importable
  from the package top level to match the documented quick-start.
- **Installation tooling** — `install.sh` (symlink or `--copy` mode), drift
  protection, and an opt-in `--autosync` `on_session_start` hook that pulls the
  latest `main` from GitHub when a Hermes session starts.

### Fixed
- RSA Wiener's attack: convergents were unpacked as `(k, d)` but produced as
  `(denominator, numerator)`, so `k`/`d` were swapped and the attack never
  recovered a private exponent; it also accepted the trivial `p*1 == n`
  factorization as success. Both fixed.
- RSA common-modulus (dropped Bézout coefficient) and small-exponent (float
  n-th root) attacks; forensics `analyze_memory`/steghide detection; engine
  `ip_to_octal` leading zero; `response_time` falls back to `requests.elapsed`;
  session-recorder param replay; orchestrator form-dedup `KeyError`;
  HTTP smuggling IPv6/credential host parsing and raw-socket TE.TE.

### Security
- Hardened the toolkit's own code: sub-agent spawn error handling, `get_doc`
  path-traversal guard, `shlex.quote` on target-derived paths, radare2 symbol
  validation, and `makedirs("")` guards.

### Integration
- Bundled SecLists wordlists relocated into the package so they survive
  `pip install` and the Hermes skill copy.

### Tooling
- Test suite expanded from 204 to 300+ tests; all under `ruff`, `ruff format`,
  and `mypy --strict`.
