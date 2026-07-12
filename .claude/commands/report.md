---
description: Write up confirmed findings into a clear, remediation-focused report.
argument-hint: [output-path]
---

Turn the confirmed findings from this session into a report. Only include findings that `/validate` confirmed — no unverified leads.

1. **Draft** each finding with: title, affected asset (in-scope), vuln class and severity, minimal reproduction steps, observed impact, and concrete remediation guidance. Write for the program's triage team, not for yourself.
2. **Generate and save** via the toolkit (the default location is retention-bounded, so it won't accumulate forever):

   ```python
   from bugbounty_ctf.advanced_tests import save_report
   path = save_report(findings, format="markdown")   # or format="json"
   print(path)
   ```

3. **Attach the scope-compliance summary** as evidence that testing stayed in bounds:

   ```python
   from bugbounty_ctf.audit_log import AuditLog
   print(AuditLog().summary())   # clean=True means no out-of-scope requests
   ```

4. **Follow the program's disclosure policy.** Do not publish, share, or disclose findings outside the program's process. Redact any real user data that surfaced during validation.
