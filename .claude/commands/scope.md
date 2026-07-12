---
description: Establish authorized scope for a HackerOne program before any testing.
argument-hint: <hackerone-program-handle>
---

Establish the testing scope for HackerOne program `$ARGUMENTS` **before doing anything else**. Testing outside an authorized allowlist is a policy violation — this command exists to make scope explicit and enforced.

1. **Confirm authorization.** The user must be an invited or eligible participant of `$ARGUMENTS`. If that is unclear, stop and ask before proceeding.

2. **Ingest the program's structured scopes** into a `ScopeGuard` (requires `H1_USERNAME` / `H1_API_TOKEN`):

   ```python
   from bugbounty_ctf.hackerone import HackerOneClient
   guard = HackerOneClient().scope_guard("$ARGUMENTS")          # all submittable host assets
   # guard = HackerOneClient().scope_guard("$ARGUMENTS", bounty_only=True)  # paid assets only
   ```

3. **Print the resulting allowlist** so the operator can see exactly what is in scope. Note that non-host assets (mobile apps, CIDRs, source repos) are intentionally not part of a host allowlist and need separate handling.

4. **Bind an audit trail** so every subsequent request's scope decision is recorded for post-engagement proof:

   ```python
   from bugbounty_ctf import SecurityScanner
   from bugbounty_ctf.audit_log import AuditLog
   scanner = SecurityScanner(base_url, scope=guard, audit_log=AuditLog())
   ```

Every later `/recon` and `/validate` step must run through this `scanner`. Do not send a single request to a host the guard rejects. When finished, `AuditLog().summary()` must show zero out-of-scope requests.
