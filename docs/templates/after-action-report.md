# After-action report — template (WP10 / WP21)

For the incident-response side. Graded against the seeded timeline, so the
reconstruction matters more than the prose.

---

**Incident ID:** `<id>` **Host:** `<hostname>` **Author:** `<you>` **Date:** `<yyyy-mm-dd>`
**Severity:** `<your assessment>` **Status:** Open / Contained / Closed

## Executive summary
Five sentences. What happened, when, what was affected, what you did, where it
stands. Written for someone who was not there.

## Timeline
UTC or local — **state which**, and use one consistently. Every row needs a
source, and the source must be an artifact you can produce.

| Time | Event | Evidence source | Confidence |
|---|---|---|---|
| | | `<log, file, hash>` | Confirmed / Probable / Assessed |

**Confidence is not optional.** Distinguishing what you *know* from what you
*infer* is the single most important habit in incident reporting. An analyst who
labels an assumption as fact is worse than one who found less.

## Initial access
How they got in, and how you know. If you could not determine it, say so
explicitly and say what evidence would have told you — that gap is itself a
finding about the logging.

## What the attacker did
Actions on objectives, in order. Map to ATT&CK where a technique genuinely fits.

## Scope and blast radius
What was touched. What was **not** touched, and how you established that.
Bounding the incident is as valuable as describing it.

## Artifacts collected
Per `docs/EVIDENCE-HANDLING.md` — path, SHA-256, when, by whom.

## Benign findings ruled out
Things that looked suspicious and were not, with the evidence that cleared them.
**This section is scored.** Investigating and correctly clearing an anomaly is
real work; silently ignoring it is not the same thing.

## Root cause
Not "malware ran". Why was it *possible*? What control was missing or failed?

## Remediation and recovery
What you did, with change record references.

## Lessons learned
What would have detected this sooner. What you would do differently. Be specific
enough that someone could act on it.
