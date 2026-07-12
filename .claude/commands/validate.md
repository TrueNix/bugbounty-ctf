---
description: Confirm a candidate finding with the minimum proof needed — cut false positives.
argument-hint: <finding description or lead>
---

Validate the candidate finding: `$ARGUMENTS`. The goal is a **confirmed, minimal, reproducible** result — not maximum impact.

1. **Scope check.** Confirm the affected host is in the authorized allowlist. Run every request through the scoped, audited `SecurityScanner` from `/scope`; an out-of-scope URL must hard-stop.
2. **Reproduce minimally.** Demonstrate the vulnerability with the smallest proof-of-concept that removes doubt. Do not exfiltrate real user data, pivot, escalate, or persist — a benign marker (e.g. a canary value, a controlled callback) is enough to prove impact.
3. **Classify honestly.** Assign a vuln class and severity. If it does not reproduce, mark it a false positive and stop — reporting noise wastes the program's time.
4. **Record what worked**, so the next similar target benefits:

   ```python
   from bugbounty_ctf.knowledge import KnowledgeBase
   KnowledgeBase().record_pattern(
       vuln_class="<class>", technique="<what worked>",
       tech_stack=["<detected-tech>", ...], target="$ARGUMENTS", notes="<concise>",
   )
   ```

Hand confirmed findings to `/report`. Never test a payload you would not be authorized to run against this exact target.
