---
description: Scoped, mostly read-only reconnaissance of an authorized target.
argument-hint: <base-url> [notes]
---

Map the attack surface of `$ARGUMENTS` **within the scope established by `/scope`**. If no `ScopeGuard` is set yet, run `/scope` first — do not recon a target you have not scoped.

Approach, least-intrusive first:

1. **Confirm the target host is in scope** before the first request. All requests go through the scoped, audited `SecurityScanner` from `/scope`.
2. **Enumerate surface** — routes, parameters, technologies, headers, auth surface — preferring passive and read-only observations before anything active. Delegate the crawl to the `recon-agent` subagent.
3. **Fingerprint the stack**, then pull relevant methodology and any techniques that worked on a similar stack before:

   ```python
   from bugbounty_ctf.knowledge import KnowledgeBase
   kb = KnowledgeBase()
   for hit in kb.suggest_methodology(["<detected-tech>", ...]):
       print(hit["source"], hit["section"])   # source="pattern" = a technique that worked before
   ```

4. **Summarize** the surface and the candidate leads worth validating — do **not** exploit here. Confirmation happens in `/validate`.

Respect the program's rate limits and any excluded paths in its policy. Keep destructive actions (data modification, DoS, spam) off the table entirely.
