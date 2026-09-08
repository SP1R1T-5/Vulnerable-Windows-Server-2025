# Detection engineering (WP19)

For a defined subset of findings the deliverable is **a rule, not a fix**. This is
the natural completion of the telemetry work: the range gives you an attack, a
host, and — once the Sysmon baseline is restored — a log to write against.

## The acceptance criteria — both halves are graded

A rule is accepted when it:

1. **Fires** on the seeded artifact, demonstrated with evidence, **and**
2. **Does not fire** on any of the benign anomalies in the `benign-anomaly`
   category.

The second half is the job. A rule that catches the malicious run key *and* the
documented vendor run key has not solved the problem — it has moved it to
whoever triages the queue. False-positive rate is part of the grade, because it
is the part of the work that actually consumes an analyst's week.

List the benign set you must not fire on:

```powershell
.\Test-RangeConfig.ps1 -Only benign-anomaly -ShowControl
```

## Getting telemetry first

Sysmon is disabled on the range as a finding (`log.live.Sysmon*`). Restore it
with the shipped baseline — that is the defined end state, so "fix Sysmon" has a
real answer rather than an argument:

```powershell
sysmon64.exe -accepteula -i ..\sysmon\sysmon-baseline.xml
```

PowerShell script-block logging is also off (`log.ps.*`). Turning it back on is a
legitimate part of building your detection surface — and it needs a change
record like any other change.

## Format

Sigma by default: portable, vendor-neutral, and what job adverts ask for. If your
course teaches a specific stack, KQL or SPL is fine — say which in the rule
header and keep the same acceptance criteria.

## Worked example

`run-key-persistence.yml` is complete and passes both halves. Read it before
writing your own, particularly the `filter_documented` block — that is the part
that took the thought, and it is the part most people leave out.

## Exercises

| Rule to write | Seeded artifact it must catch | Technique |
|---|---|---|
| `lsass-access.yml` | LSASS handle acquisition (the range confirms lsass is dumpable) | T1003.001 |
| `beacon-interval.yml` | The 300-second TCP check-in from `svc.ps1` | T1095 |
| `scheduled-task-created.yml` | `System Update Check` / `Windows Health Monitor` | T1053.005 |
| `winlogon-shell.yml` | The `Winlogon\Shell` hijack | T1547.004 |
| `sysmon-tampering.yml` | The service being disabled again | T1562.001 |

For each, record in your write-up: what it fires on, what it deliberately does
not, and **what an attacker would have to change to evade it**. That last
question is what separates a detection engineer from someone who writes greps.

## Coverage

`Test-RangeConfig.ps1 -ShowControl` prints ATT&CK coverage for what is actually
in place on the box. Argue your rules against that map — including where you
decide a technique is *not* worth a rule, which is a legitimate and defensible
answer if you can say why.
