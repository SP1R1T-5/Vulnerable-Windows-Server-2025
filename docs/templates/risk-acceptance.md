# Risk acceptance — template (WP14)

For findings you are **deliberately not fixing** this round. Accepting risk is a
real, senior activity — it is not the same as ignoring something, and the
difference is entirely in this document.

You will be graded on the quality of these as much as on what you fixed.

---

**Acceptance ID:** `RA-<yyyy>-<nnn>`
**Finding(s):** `<IDs>`
**Accepted by:** `<name and role — must be someone with authority to accept it>`
**Date:** `<yyyy-mm-dd>` **Review date:** `<when this gets revisited — not "never">`

## What we are not fixing, and why
The finding, and the honest reason. Valid reasons include cost, a dependency
that is not ready, a maintenance window that does not exist yet, or a business
process that would break. "We ran out of time" is a valid reason if it is true;
"it is not really a problem" usually is not, and contradicts your own finding.

## Compensating controls
What reduces the risk in the meantime. If the answer is genuinely "nothing",
write "none" — an honest gap is more useful than an invented mitigation.

## Residual risk
What could still happen, and roughly how bad. Someone senior is signing this;
give them what they need to sign it.

## Trigger for revisiting
What would change this decision — a new exploit, a vendor patch, the legacy
application being retired, the next audit.
