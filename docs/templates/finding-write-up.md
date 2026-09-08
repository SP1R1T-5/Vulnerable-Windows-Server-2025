# Finding write-up — template

One per finding. This is the unit of work in every assessment, pentest report and
SOC escalation you will ever write. If a reader cannot act on it without asking
you a question, it is not finished.

---

**Finding ID:** `<from the control table — e.g. smb.srv.require>`
**Title:** `<short, specific, no jargon: "SMB signing not required on the domain controller">`
**Severity:** Critical / High / Medium / Low — *and say what drove it, not just the label*
**Control:** `<NIST SP 800-53 / CIS — from Test-RangeConfig.ps1 -ShowControl>`
**ATT&CK:** `<technique ID, if one genuinely applies>`
**Host:** `<hostname>` **Date:** `<yyyy-mm-dd>` **Author:** `<you>`

## Summary
Two or three sentences. What is wrong, on what, and why anyone should care.
Write this last, and write it for someone who will read only this paragraph.

## Evidence
Command run, output, and the artifact hash (see `docs/EVIDENCE-HANDLING.md`).
Evidence that is not reproducible is not evidence.

```
<command>
<output>
```

- Artifact: `<path>` SHA-256 `<hash>` collected `<yyyy-mm-dd hh:mm>` by `<you>`

## Impact
What an attacker gains. Be concrete and bounded — "an attacker on the same
subnet can relay authentication to this host and execute code as the
authenticating user" beats "this is insecure". State what it does **not** give
them too; overstating impact is how junior analysts lose credibility.

## Reproduction
Numbered steps someone else can follow on a clean box. If you cannot write
these, you have not confirmed the finding.

## Remediation
The **correct** fix, not the quickest one. Name the setting, the value, and where
it should be set (GPO vs local registry — say which and why). If the correct fix
needs something the environment lacks, say so.

## Residual risk / caveats
What remains after the fix. Anything you could not test. Anything you are unsure
of — say so plainly; "I could not confirm X" is a professional statement.

## References
Vendor documentation, CIS benchmark section, CVE, ATT&CK page.
