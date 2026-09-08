# Change record — template (WP16)

**No change record, no marks.** A remediation without one scores zero even when
it is technically correct. That is not bureaucracy for its own sake: in a real
estate, an unannounced change that breaks production is a worse outcome than the
vulnerability you were fixing.

---

**Change ID:** `CHG-<yyyy>-<nnnn>`
**Raised by:** `<you>` **Date raised:** `<yyyy-mm-dd>`
**Related finding(s):** `<finding IDs>`

## What is changing
The specific setting, its current value, and its target value. One change per
record — bundling five settings into one record means you cannot roll back one.

## Why
Link to the finding. One sentence of risk, in business terms.

## Blast radius
What else touches this setting. Who or what could break. Be specific about
systems and users, not "minimal impact" — that phrase means you have not looked.

> Worked example from this range: turning SMB signing back on is correct, and on
> a domain controller SYSVOL and NETLOGON already force it. Turning off
> `EnableSecuritySignature` does nothing there (finding F40). A change record
> that predicted "no effect on a DC" would have saved a day.

## Rollback plan
The exact command or steps to put it back, and how long that takes. If you
cannot state the rollback, the change is not ready.

## Testing
How you will confirm it worked, and how you will confirm nothing else broke.
Both. `Test-RangeConfig.ps1` proves the first, not the second.

## Window
When it will be applied. Is that inside an approved maintenance window?

## Approval
| Role | Name | Decision | Date |
|---|---|---|---|
| Change approver | | Approved / Rejected / Deferred | |

**If rejected or deferred:** what compensating control do you propose in the
meantime? A rejected change is a normal outcome, not a failure.
