# Exercise rubric — how the range is scored (WP14 / WP16 / WP17)

The point of this document is that the range stops rewarding "fix everything as
fast as possible", which no real organisation does and no employer wants.

Three rules change the game:

1. **You have a budget.** You cannot fix all of it, and you are not supposed to.
2. **Unrecorded changes score zero.** No change record, no marks.
3. **False positives cost marks.** Escalating everything is a losing strategy.

---

## 1. The budget (WP14)

Each round the instructor sets:

| Constraint | Typical value | Why it exists |
|---|---|---|
| Engineer-hours | 8 | Forces triage |
| Maintenance windows | 1 (03:00–04:00) | Some fixes need a reboot; you get one |
| Approvals available | 3 | The change board is not infinite either |

At least one finding will carry a **stated business cost** — remediating it
breaks a named legacy application. Fixing it anyway without raising that is a
failure of judgement, not a success of thoroughness.

The control table currently ships **130 controls**. You are not fixing 130 things
in 8 hours. That is the entire lesson.

### What you hand in

- A ranked remediation plan ([POA&M](templates/poam.md)) — ordered by *your*
  argument, not by severity label.
- A [risk register](templates/risk-register.md) covering everything you found.
- A [risk acceptance](templates/risk-acceptance.md) for everything you are not
  fixing. **All of it.** "Not fixed and not mentioned" is the worst outcome
  available and scores below "not fixed, accepted, justified".

### How it is scored

| Weight | Criterion |
|---|---|
| 35% | **Quality of the prioritisation argument.** Why these, in this order, under this budget. |
| 25% | Quality of the risk acceptances — honest reasons, real compensating controls, sensible review dates. |
| 20% | Technical correctness of the fixes actually applied (`Test-RangeConfig.ps1` confirms). |
| 20% | Written deliverables ([finding write-ups](templates/finding-write-up.md), [executive summary](templates/executive-summary.md)). |

**Note what is *not* weighted: the number of findings fixed.** A student who
fixes 12 and accepts the rest with defensible reasoning beats one who fixes 40 at
random. Say this to students at the start — otherwise they optimise for the
wrong thing and feel cheated afterwards.

### The prioritisation trap

Findings are seeded so that at least one is **cheap and low-risk** and at least
one is **expensive and critical**. Run the round twice with different budgets. If
a student's ranking does not change, they sorted by severity label — they did not
prioritise.

## 2. Change control (WP16)

Every remediation needs a [change record](templates/change-record.md) *before* it
is applied.

- **No record → the fix scores zero**, even if technically perfect.
- At least one change will be **rejected or deferred** by the instructor acting
  as change board. The student must then propose a compensating control. Being
  told "no" is a normal working experience and most students have never had it.
- At least one approved change **will break something**. The rollback plan is the
  point. (SMB signing against a legacy client is the natural candidate; note that
  on a DC, SYSVOL and NETLOGON force signing regardless — see finding F40, which
  a good blast-radius section would have predicted.)

## 3. Benign anomalies (WP17)

The box contains artifacts that look suspicious and are entirely legitimate, each
with a discoverable exculpatory trail under `C:\IT\change-records\`.

Scoring runs **both directions**:

| Outcome | Marks |
|---|---|
| True positive found and reported | full |
| True positive missed | lose |
| Benign artifact investigated and correctly cleared, **with evidence** | full |
| Benign artifact escalated as a finding | lose |
| Benign artifact silently ignored | no marks — investigating and clearing is the work |

That last row matters. "I did not report it" is not the same as "I cleared it".
The [after-action report](templates/after-action-report.md) has a
*Benign findings ruled out* section for exactly this.

**Instructor note (F24):** the benign set is branded `Northwind` and documented
under `C:\IT`. The range's own seeded persistence is `SysHealth` /
`WinTelemetryHelper` under `C:\ProgramData\SysTasks`. Live red-cell implants are
neither. Keep those three naming schemes distinct or none of this is adjudicable.

The authoritative benign list is the `benign-anomaly` category:

```powershell
.\Test-RangeConfig.ps1 -Only benign-anomaly -ShowControl
```
