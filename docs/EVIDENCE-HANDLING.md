# Evidence handling (WP21)

One page. This is not a forensics course — the goal is **habits and defensible
notes**, not tool mastery. The difference being taught is between "I found it"
and "I can prove it", and it is the difference between a report that survives
scrutiny and one that does not.

---

## The five rules

1. **Order of volatility.** Collect what disappears first: running processes and
   network connections, then memory, then the event logs, then files on disk,
   then anything already backed up. Rebooting to "clean up" destroys the top
   three.
2. **Hash on collection.** SHA-256, recorded at the moment you take the copy.
   A hash produced later proves nothing about what you collected.
3. **Work from copies.** Analyse the copy, never the original. If you must act on
   the live system, record what you ran and when.
4. **Record who, what, where, when.** Every artifact. An artifact with no
   provenance is an anecdote.
5. **Do not contaminate.** Every command you run changes the box — process
   creation events, prefetch, timestamps. That is unavoidable; what matters is
   that your actions are *recorded* so they can be told apart from the attacker's.

## The one that costs people marks

**Remediating before collecting destroys the evidence.**

If you delete the scheduled task, remove the run key and reboot, you have made
the box safe and made the incident unreconstructable. Nobody can now say what
happened, when it started, or whether it is gone.

Containment sometimes genuinely outranks collection — that is a judgement call,
and a defensible one. What is not defensible is making it by accident. If you
choose to contain first, **write down that you chose it and why**.

## Collection log

Keep one per incident. A text file is fine.

```
ARTIFACT   C:\ProgramData\SysTasks\health.ps1
SHA-256    <hash>
COLLECTED  2026-09-08 14:22 local  by <you>
METHOD     Copy-Item to E:\evidence\, hashed at source and destination
NOTES      Referenced by the SysHealth run key and by two scheduled tasks.
```

Useful one-liners:

```powershell
Get-FileHash -Algorithm SHA256 <path>
Get-ScheduledTask | Select-Object TaskName,TaskPath,State | Export-Csv <out>
wevtutil epl Security <out>.evtx
Get-NetTCPConnection | Where-Object State -eq 'Established'
```

## What gets graded

- Every artifact cited in your [after-action report](templates/after-action-report.md)
  has a hash and a collection entry. **Uncited or unhashed evidence earns no credit.**
- Your timeline separates **Confirmed / Probable / Assessed**. Labelling an
  inference as a fact costs more than finding less would have.
- Your actions are distinguishable from the attacker's in your own timeline.
- If you contained before collecting, you said so and justified it.
