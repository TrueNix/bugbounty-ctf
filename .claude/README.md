# Claude Code command & subagent layer

A thin, Claude-Code-native front end over the `bugbounty_ctf` package that
packages the **authorized** workflow — scope → recon → validate → report — with
scope enforcement and a scope-compliance audit trail baked in. It adds no new
capability; it orchestrates existing modules with authorization and
accountability as the backbone.

## Slash commands (`.claude/commands/`)

| Command | Purpose |
| --- | --- |
| `/scope <program>` | Ingest a HackerOne program's scope into a `ScopeGuard` and bind an `AuditLog`. **Run this first.** |
| `/recon <base-url>` | Scoped, mostly read-only attack-surface mapping. |
| `/validate <lead>` | Confirm a candidate finding with the minimal proof needed; cut false positives. |
| `/report [path]` | Write confirmed findings into a remediation-focused report with the scope-compliance summary attached. |

## Subagents (`.claude/agents/`)

`recon-agent`, `validator`, and `report-writer` mirror the workflow stages, each
with a narrow tool scope.

## Guardrails

- **Scope first.** `/scope` establishes an allowlist from the program's own
  structured scopes; every request routes through a `ScopeGuard` that hard-stops
  out-of-scope hosts.
- **Everything is recorded.** Requests flow through a `SecurityScanner` bound to
  an `AuditLog`, so `AuditLog().summary()` can prove testing stayed in bounds.
- **Minimal proof, no escalation.** Validation stops at a benign, reproducible
  proof-of-concept — no real-data exfiltration, pivoting, persistence, or DoS.
- **Authorized use only.** These commands assume the operator is an eligible
  participant of the target program and follow its disclosure policy.
