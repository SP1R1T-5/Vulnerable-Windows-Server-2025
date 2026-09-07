# Changelog

All notable changes to the Windows Server 2025 Cyber Range builder.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/). Dates are `YYYY-MM-DD`.

Update this file whenever behavior changes. Group entries under **Added / Changed /
Fixed / Removed**, newest date on top.

## [Unreleased]

### Changed — 2026-09-06 (project tidy: docs brought in line with the code)
No stray files existed; the clutter was stale *content* pointing at a build model
that no longer applies.

- **`docs/SETUP-GUIDE.md` rewritten** around the decision that actually matters
  first: **single VM vs class of VMs**. A class build must use `-Mode Image`,
  because an image cut after promotion reintroduces F16 and cannot be repaired by
  renaming clones. Adds the full golden-image -> sysprep -> clone -> personalize
  flow, the per-clone identity table, the cross-VM acceptance tests, the current
  script inventory, and the expected N-A/WARN rows so a clean run is recognisable.
- **`HANDOFF.md`**: file map now lists all nine scripts with their roles;
  Phase 1-verified and WP2 entries added; **Next steps** now leads with the one
  outstanding WP2 acceptance test (forge a golden ticket on clone A, confirm
  clone B rejects it) and then WP3 -> WP1 -> WP11 -> WP5.
- **`README.md`**: layout section refreshed from four scripts to nine.
- **`Invoke-RangeBuild.ps1` REMOVED.** (Marked deprecated earlier the same day,
  then deleted on the operator's call.) It worked, but
  it is a second entry point that does **not** carry the F29 domain-member check,
  analyst provisioning, `Test-PhaseClean`, the F35 post-servicing update re-assert,
  or `-Mode` — so it can weaken a box the engine would have refused. The header
  now names each gap and points at `Repair-RangeConfig.ps1` / `Reset-CyberRange.ps1`.
  Kept only because it can re-run a whole category script, which the repair tool
  (which fixes individual controls) cannot.

### Added — 2026-09-06 (WP2 — closes F16: every clone shared krbtgt and the domain SID)
**The fix is structural, not a patch.** Cut the golden image BEFORE promotion, and
let each clone promote its own forest. A unique domain SID and a unique `krbtgt`
then come for free, because promotion generates them. An image cut *after*
promotion cannot be repaired by renaming — a golden ticket forged on one student's
VM is valid on every peer.

- **`-Mode Image`** (`Stage-CyberRange.ps1` -> `Setup-CyberRange.ps1`): runs Phase 1,
  writes `IMAGE-READY.txt` with the cloning procedure, and stops **unpromoted**.
  Deliberately does not register the resume task, so the image cannot promote
  itself on next boot. `-Mode AllInOne` (default) is exactly today's behaviour, so
  single-VM development is unaffected.
- **`Get-RangeCloneIdentity`** in `RangeCommon.psm1` — the single source of truth
  for per-clone identity and secrets, derived as
  `HMAC-SHA256(MasterSecret, "<cloneId>/<purpose>")`. Both the writer and the
  recovery tool call it, so the derivation cannot drift and strand a clone.
- **`Initialize-RangeClone.ps1`** — per-clone first boot, run by a range admin.
  Refuses to run on an already-promoted host (naming F16 as the reason), derives
  the identity, rewrites the staged config **preserving comments**, verifies the
  rewrite took and rolls back if not, re-asserts the operator accounts with the new
  secrets, renames the computer, then hands to Phase 2 for promotion.
- **`Get-RangeCloneSecret.ps1`** — instructor-side recovery. One master secret
  recomputes any clone's credentials; no bookkeeping across thirty VMs. `-All 30
  -AsCsv` produces the key sheet.

**Deviation from the WP2 spec, deliberate:** the spec listed four derived secrets
and omitted `Analyst.Password`. That is a hole. `analyst` is a Domain Admin on
every clone, and since each clone is its own forest, a shared analyst password
means a student who learns it on their own box can log into every peer's DC as
that peer's analyst — the same cross-VM compromise F16 is about, through a
different door. Now derived per clone. Five secrets, verified distinct.

**Also simpler than the spec:** WP2 called for a new Phase 1.5. Not needed —
`Initialize-RangeClone.ps1` performs the personalization and sets state to Phase 2
directly, so the existing state machine is untouched.

Verified locally: derivation is deterministic (`-CloneId 7` == `07`), isolated per
clone and per master secret, 28 chars, complexity-compliant, shell-safe; the
config rewrite hits all six values, does not leak between the `BreakGlass` and
`Analyst` blocks, preserves all 48 comments and still imports; all 31 files parse.
**Not yet run on hardware** — the acceptance test is cross-VM: forge a golden
ticket on clone A and confirm clone B rejects it.

### PHASE 1 COMPLETE — 2026-09-06
First clean end-to-end build verified on hardware (`WIN-UGR8U7OFA11`, Server 2025,
promoted DC for `range.lab`). **`Test-RangeConfig.ps1` reports 0 FAIL.**

Confirmed live: ESC1 published and enrollable, Kerberoast (RC4-stamped SPNs),
AS-REP roasting, DCSync, GenericAll on Domain Admins, constrained and
unconstrained delegation, MAQ=10, GPP cpassword in SYSVOL, SMB1 with signing off,
LSASS dumpable via OpenProcess, full persistence set, working break-glass and
analyst accounts.

Journey from the first field log to zero failures, for the record: F26 (RC4-only
KDC locking out every domain account), F27 (Phase 4 ACL locking the build out of
its own state file), F28 (DC not using itself for DNS, killing ADWS), F29
(domain-member preflight), F30 (resume task hanging on a prompt), F31 (password
policy rejecting seeded accounts), F32 (Stage inheriting stale state), F33/F34
(ESC1 as a V1/V2 hybrid the CA rejected), F35 (servicing re-enabling Windows
Update), F36/F37 (event-log size unit confusion), F38 (accepted deviation).

**Not yet addressed:** the topology work in `docs/IMPROVEMENT-PLAN.md`, above all
**F16** — cloning after promotion gives every participant VM the same `krbtgt` and
domain SID, so a golden ticket forged on one box owns all of them. Do not
distribute an image until that is resolved.

### Added — 2026-09-06 (Reset-CyberRange.ps1 — teardown without a snapshot revert)
Undoes the range in place: re-hardens the machine and removes the accounts,
persistence, shares and AD attack paths. **Dry run by default**; `-Execute`
applies, and then only after typing `TEARDOWN` at a prompt.

Nine categories, each skipping cleanly when the artifact is already gone so a
second run is a no-op: persistence, credentials, machine-security, network,
logging, defenses, artifacts, accounts, dc. `-Only` scopes it.

Safety properties, several learned the hard way in this project:
- **Never removes the account running the script.** Explicit check.
- **Operator accounts (`analyst`, break-glass) are kept by default** —
  `-RemoveOperatorAccounts` to drop them. Removing your way back in while the box
  is still half-weakened is how the field lockout happened.
- **The Remote Desktop firewall rule is re-enabled before the profiles are**, and
  the script warns when it detects a remote session, because re-hardening the
  firewall / NLA / WinRM encryption can disconnect the operator mid-run.
- **The IFEO accessibility-shell removal is treated as the priority item** — it is
  a live authentication bypass, not just an artifact.
- **The VSS shadow copy is deleted**: it is the HiveNightmare artifact and can
  carry the SAM/SYSTEM hives, so leaving it is a real credential exposure.

The script is explicit about what a teardown **cannot** do, in the header and
again in the closing summary: DC promotion (domain SID and krbtgt persist;
`-RemoveDomain` demotes but a demoted DC is not a never-promoted server), exposed
credentials (every seeded password, the overwritten Administrator password and
the DSRM password are burned), missed patches, and stored LM hashes / cached
credentials. The stated rule is: if the box is going back to anything that
matters, rebuild it.

The DC security-template downgrades are deliberately left for **manual** removal
via GPMC — automated editing of a live DC security template is riskier than the
misconfiguration it would remove.

Engine semantics verified in a harness (WOULD/SKIP on dry run; DONE/SKIP/ERROR on
execute) and the elevation guard confirmed. **Never run against a built range.**

### Changed — 2026-09-06 (F38 — event-log channel size is an ACCEPTED DEVIATION)
Closed after five attempts. The Security/System channel size resisted every
supported mechanism on this Server 2025 DC:

| Mechanism | Result |
|---|---|
| `Services\EventLog\<ch>\MaxSize` (legacy) | written; not authoritative |
| `WINEVT\Channels\<ch>\MaxSize` | written; EventLog service does not reload it without a restart |
| `wevtutil sl <ch> /ms:` | denied on Security (needs SeSecurityPrivilege) |
| `SOFTWARE\Policies\...\EventLog\<ch>\MaxSize` (admin template) | KB-denominated -> produced 1 GB. Reverted |
| `[Security Log] / [System Log] MaximumLogSize` (security template) | MB-denominated -> produced 1 GB. Removed |

The two mechanisms that made it *worse* are no longer written, and `dc\60` still
attempts the WINEVT/wevtutil path best-effort. When the channel is still large it
is now reported **N-A with the reason**, not FAIL, in `Test-RangeConfig.ps1`,
`Repair-RangeConfig.ps1` (both the direct row and the post-gpupdate row), and
`dc\60` (ERROR -> WARN).

Deliberately **kept as a row rather than deleted**, so the control stays in the
scoring baseline (NIST AU-4/AU-11, CIS 8.3) and this is not re-opened from
scratch. The range simply does not pre-break it; blue team can still be graded on
it. It gates no attack path — its only role was making evidence roll over faster.

Process note: this consumed five build/repair cycles, three of them on my
inferences from pass/fail summaries. The registry + `GptTmpl.inf` + live-value
dump that actually identified the mechanism should have been the first step, not
the fourth.

### Fixed — 2026-09-06 (F37 — the log-size culprit found, with evidence)
Diagnosed from the DC instead of inference. Three data points settled it:
- `Get-ItemProperty HKLM:\SOFTWARE\Policies\...\EventLog\Security` returned
  **nothing** — the F36 policy override was gone and gpupdate had not restored it.
  The policy key was exonerated.
- `GptTmpl.inf` still carried `[System Log] MaximumLogSize=1024` and
  `[Security Log] MaximumLogSize=1024`.
- Both channels sat at **1073741824** bytes, which is 1024 x 1 MB.

So the legacy security-template sections are **not** ignored on Server 2025 —
my F36 comment claiming they were was wrong. They are applied, and the value is
read as **megabytes**, not the documented kilobytes. `1024` therefore requested
1 GB: the exact opposite of the intent, and the sole remaining source once the
policy key was removed.

Two fixes:
- **Remove the `[System Log]` / `[Security Log]` sections** rather than trying to
  pick a correct number. The unit does not match the documented format, so no
  value there is trustworthy; the WINEVT channel config owns the size instead —
  the path that demonstrably produced a correct 1052672.
- **Ordering (my bug):** the log-size writes ran BEFORE `gpupdate /force`, so the
  refresh immediately overwrote them. Removing a setting from a security template
  also does not roll back the value it already applied (security policy tattoos),
  so the small size must be written *after* the refresh. `gpupdate` now runs
  first, then the legacy/WINEVT/wevtutil writes, then a verification pass that
  reports the live channel size and says explicitly when a reboot is needed.

Also fixed: `Get-WinEvent -ListLog <name>` returns each channel **twice** on this
DC (confirmed — it returns one object elsewhere), which is why every message
printed the size doubled. Both scripts now filter to the exact `LogName` and take
a single object.

### Fixed — 2026-09-06 (F36 REVERTED — the policy MaxSize is KB, and it was never needed)
F36 was wrong and made things worse: it set
`SOFTWARE\Policies\Microsoft\Windows\EventLog\<ch>\MaxSize = 1048576` believing
the value was bytes. It is **KB**, so it demanded 1 GB — and the System channel,
which had been PASSING at 1052672, regressed to FAIL alongside Security
(126 PASS/1 FAIL -> 123 PASS/2 FAIL).

The evidence also shows the policy key was never needed. Before F36 the System
channel passed at 1052672, set purely by `wevtutil` -> `WINEVT\Channels`. That
path works. Security fails only because `wevtutil sl Security` is denied (it
requires SeSecurityPrivilege), so the correct fix is to write
`WINEVT\Channels\Security\MaxSize` **directly** — which F36 also added, and which
is kept — not to layer a GPO override on top.

`dc\60-dc-security-gpo.ps1` now:
- **Removes** the bad `[Registry Values]` EventLog entries from the DC security
  template (new `Remove-InfKey`), so re-running cleans a box that ran the bad
  version rather than leaving 1 GB re-applying on every refresh.
- **Deletes** the local `SOFTWARE\Policies\...\EventLog\<ch>\MaxSize` override
  (new non-throwing `Get-RegValueSafe`), leaving the WINEVT channel config to win.
- Keeps the WINEVT + legacy writes and the wevtutil error reporting.

Lesson recorded: the KB/bytes ambiguity was flagged as a risk when F36 shipped but
was shipped anyway on a guess. A setting whose units are uncertain should be
written, verified against live state, and corrected in the same run — or not
written at all when a working path already exists.

### Fixed — 2026-09-06 (F36 — Security log size used a pre-Vista template section)
Down to a single FAIL: the Security channel stayed at the 20 MB DC default
through a `gpupdate /force` **and** a reboot, while every other control passed.

The tell was inside `dc\60-dc-security-gpo.ps1` itself: the SMB-signing downgrade
in that same file works, and it is a `[Registry Values]` entry. The log sizes were
written as `[System Log] / [Security Log] MaximumLogSize` — the **pre-Vista**
security-template sections, which modern Windows ignores for the Windows Event Log
channels. So they were being written and silently discarded on every refresh.

The setting Vista+ honours is the Event Log Service administrative template at
`SOFTWARE\Policies\Microsoft\Windows\EventLog\<Channel>\MaxSize`, which overrides
both the legacy `Services\EventLog` key and the WINEVT channel config. That is now
expressed as a `[Registry Values]` entry — the same mechanism already proven to
work in this file — and written locally as well so it applies before the next
policy refresh rather than only after it. Four locations are now covered:

| Location | Role |
|---|---|
| `SOFTWARE\Policies\...\EventLog\<ch>\MaxSize` | **wins at runtime** (GPO admin template) |
| `WINEVT\Channels\<ch>\MaxSize` | what `Get-WinEvent -ListLog` reports |
| `Services\EventLog\<ch>\MaxSize` | legacy; what the registry-only check reads |
| `[Security Log] MaximumLogSize` | pre-Vista, ignored — kept only for old tooling |

Also: `wevtutil` failures are now logged instead of swallowed (the Security
channel needs SeSecurityPrivilege and refuses this call more often than not).

Unit caveat recorded in the script: `MaxSize` under the policy key is in **bytes**
despite the ADMX being labelled KB. If the channel comes back at ~1 GB, that one
line changes to `1024`. A wrong guess fails the existing check rather than passing
silently.

### Fixed — 2026-09-06 (F35 — servicing operations silently re-enable Windows Update)
ESC1 publication and the System log channel both cleared, but two NEW failures
appeared in the same run: `wuauserv` was no longer disabled (both the registry
and the live check).

Cause: **any servicing operation re-enables the Windows Update client.**
`scripts/dc/20-adcs-esc1.ps1` opens with
`Install-WindowsFeature ADCS-Cert-Authority, ADCS-Web-Enrollment`, and the
component store may need to pull payload from Windows Update, so CBS/DISM turns
`wuauserv` back on. Nothing re-asserted the lockdown afterwards. The signature is
distinctive: `wuauserv` flipped while `WaaSMedicSvc` and `UsoSvc` stayed
disabled, i.e. the servicing stack specifically, not Update Medic self-repair.

New `Disable-RangeUpdateServices` in `modules/RangeCommon.psm1` re-asserts
`Start=4` + stopped for all three update services, logs only what it actually
changed, and records a manifest row. Idempotent. Called from:
- `scripts/dc/20-adcs-esc1.ps1` (AD CS role install)
- `scripts/70-legacy-services.ps1` (SNMP capability, TFTP/PSv2 features)
- `Setup-CyberRange.ps1` Phase 4 as a catch-all before the range is declared ready

This class of regression will recur for any feature added later, which is why the
catch-all is in finalize rather than only at the call sites.

### Fixed — 2026-09-06 (F34 — ESC1 template was a V1/V2 hybrid, so the CA rejected it)
`certutil -SetCATemplates +RangeUserESC1` in the field returned
`Invalid Template` / `ERROR_NOT_FOUND (0x80070490)` — certutil resolved the name
but rejected the object. Two defects in `scripts/dc/20-adcs-esc1.ps1`:

- **Schema-version mismatch (the root cause).** The clone source, the built-in
  `User` template, is **schema version 1**. `msPKI-Template-Schema-Version` was
  copied verbatim, and then the ESC1 flips wrote `msPKI-Certificate-Name-Flag`,
  `msPKI-Enrollment-Flag` and `msPKI-RA-Signature` — all **V2** concepts. The
  result declared V1 while carrying V2 attributes. certutil validates a template
  against its declared schema version and rejects the mismatch, which is why every
  individual ESC1 attribute checked out in `Test-RangeConfig.ps1` while
  publication failed. The template is now explicitly declared **V2**.
- **`msPKI-Private-Key-Flag` was never copied**, and it is mandatory for V2+.
  Added to the copy list, and defaulted to `0x10` (CT_FLAG_EXPORTABLE_KEY) if the
  source lacks it. `msPKI-Minimal-Key-Size` (2048) and
  `msPKI-Template-Minor-Revision` are likewise guaranteed.

These repairs sit outside the create-only branch, so re-running the script
**fixes an already-broken template in place** rather than requiring it to be
deleted first.

Confirm on the box with `certutil -v -dstemplate RangeUserESC1` — schema version
should read 2, not 1. Still unproven on hardware.

### Fixed — 2026-09-06 (post-repair triage: 5 FAIL -> 3, two of which were self-inflicted)
The repair pass cleared SMB signing via the GPO route (proving that approach) and
turned PSv2 into N-A. Root-causing the three that remained:

- **System event-log channel was a FALSE FAIL.** The build asks for 1048576 bytes;
  Windows committed **1052672** — exactly one 4096-byte page more. The test used
  `-le 1048576`, so a setting that *had* applied was reported as not applied.
  `Test-RangeConfig.ps1` and `Repair-RangeConfig.ps1` now allow a 64KB
  allocation-granularity margin (threshold 1114112), which accepts the adjusted
  value and still fails the 20 MB DC default by a wide margin. Verified against
  the observed values.

- **Security event-log channel: the wrong registry key was authoritative, and the
  failure was silent.** `Services\EventLog\<channel>\MaxSize` is the LEGACY value —
  writing only that made the *registry* check pass while the live channel stayed at
  the 20 MB DC default, which is exactly the split the field run showed
  (`MaxSize=1048576` PASS, channel 20971520 FAIL). The channel's real config lives
  under `WINEVT\Channels\<channel>\MaxSize`. Compounding it, the repair piped
  `wevtutil` to `Out-Null`, so a failure on the Security channel (which needs
  SeSecurityPrivilege and is commonly denied) was invisible and reported as
  success. The repair now writes **both** keys, checks `$LASTEXITCODE`, and prints
  the actual wevtutil error.

- **ESC1: the template's OID changed on every run.** `dc\20-adcs-esc1.ps1` minted a
  new `msPKI-Enterprise-Oid` unconditionally, so each run changed the template's
  identity out from under the CA (the two field runs show different OIDs) and left
  orphaned OID objects behind. A CA that cached the previous OID can then refuse to
  publish. It now mints **only** when the template has no OID or is still sharing
  the User template's; otherwise it reuses and logs the existing one. Whether this
  is the whole cause of the publish failure is still unproven — see the diagnostics
  in HANDOFF.

### Added — 2026-09-06 (Repair-RangeConfig.ps1 — write-enabled companion to the checker)
`Test-RangeConfig.ps1` reports; this repairs. For each control it tests live
state, applies a fix only if the control is wrong, then **re-tests** and reports
what actually changed (`OK` / `FIXED` / `STILL-FAILING` / `N-A` / `ERROR`).
A fix that does not move the test is reported STILL-FAILING, never FIXED.

Three properties that make it more than a re-run of the build:
- **Repair pass, not a build pass.** Touches only controls currently in the wrong
  state; no promotion, no account seeding, no reboot. Safe on a finished range.
- **Handles the DC Group Policy class honestly.** On a DC the Default Domain
  Controllers Policy owns SMB signing, `NoLMHash` and the event-log sizes via the
  Security CSE and re-asserts the SECURE value on every refresh, so a local
  registry write "succeeds" then reverts. Those are delegated to
  `scripts\dc\60-dc-security-gpo.ps1`, after which the script runs
  **`gpupdate /force` and re-tests** — so a repair that will not survive policy
  refresh is caught here instead of on the next reboot.
- **Separates "not applied" from "cannot be applied".** Live SAM/SYSTEM/SECURITY
  hive DACLs and the removed PowerShell v2 payload are reported `N-A` with the
  reason, never "fixed".

Delegates to the existing tested fixers (`dc\20-adcs-esc1.ps1`,
`dc\60-dc-security-gpo.ps1`) rather than duplicating their logic.
Supports `-WhatIf`, `-Only <categories>`, `-SkipGpo`.
Engine logic verified in a harness: OK / FIXED / STILL-FAILING / ERROR and
`-WhatIf` all behave correctly.

### Fixed — 2026-09-06 (false FAIL + a mojibake bug class)
- **PowerShell v2 check reported a false FAIL.** The field run returned an empty
  `State=` from DISM (payload absent / servicing busy), which fell through to the
  `else` branch and blamed the build. Empty/whitespace State is now `N-A` with the
  reason. All four branches verified.
- **Non-ASCII inside quoted strings in BOM-less scripts.** PowerShell 5.1 reads a
  UTF-8 file without a BOM as CP1252, so an em-dash (`U+2014`) decodes to bytes
  ending in `0x94` — a smart *quote* — which terminated a string early and broke
  parsing outright. Found while adding the repair script; swept the whole repo and
  fixed two more latent instances in operator-facing messages
  (`60-logging-visibility.ps1`, the F29 domain-member error in
  `Setup-CyberRange.ps1`). Those two did not break parsing but rendered as
  mojibake on the console. All 28 `.ps1`/`.psm1` files parse clean.

### Added — 2026-09-06 (F33 — DC-GPO-reverted controls; ESC1 publish; unsettable checks)
A clean end-to-end build still reported 11 FAILs. Root-caused into three classes
and fixed each at the real cause rather than re-writing local registry the DC
keeps reverting.

**F33a — four controls reverted by the Default Domain Controllers Policy.**
`NoLmHash=0`, SMB server signing off, and the 1 MB Security/System log sizes are
all owned by the Security CSE of the built-in **Default Domain Controllers
Policy**, which re-enforces the *secure* value on every gpupdate/reboot. Local
registry writes (in `20-credential-exposure.ps1`, `40-smb-network.ps1`,
`60-logging-visibility.ps1`) can't win against a Security-CSE GPO setting, so they
silently reverted. New script **`scripts/dc/60-dc-security-gpo.ps1`** writes the
weak values into the DC policy's `GptTmpl.inf` security template
(`NoLMHash=4,0`, `LanManServer\...\RequireSecuritySignature=4,0`, `[Security Log]`
/`[System Log] MaximumLogSize=1024`), bumps the GPO version, also shrinks the log
channels directly (promotion resets them once), and runs `gpupdate /force`. Runs
LAST in the DC block. New config toggle `DC.SecurityGpoDowngrade` (default `$true`).
This is also the better teaching artifact — the misconfig now lives in Group
Policy, where blue team must find and remediate it.

**F33b — ESC1 template created in AD but never enrollable.** `[live] ESC1 template
published on the CA` stayed FAIL because `certutil -SetCATemplates` / `Add-CATemplate`
can silently no-op if the CA hasn't cached the template. `scripts/dc/20-adcs-esc1.ps1`
now publishes authoritatively by appending the template CN directly to every
`pKIEnrollmentService` object's `certificateTemplates` attribute via ADSI, then
restarts CertSvc and verifies with `certutil -CATemplates`.

**F33c — two checks tested conditions that cannot hold on a running host.** The
live SAM/SYSTEM/SECURITY DACLs cannot be rewritten while the kernel holds the
hives open (`icacls /grant` is denied even after takeown); the exploitable
HiveNightmare artifact on 2025 is the VSS shadow copy, which passes. PowerShell v2
is `DisabledWithPayloadRemoved` on 2025 and can't be enabled without Windows
Update (disabled by the build). `Test-RangeConfig.ps1` now reports these as
**N-A** with an explanation instead of FAIL. Expected next build:
119 PASS → clears the 4 GPO controls + ESC1 publish; the 3 HiveNightmare + 1 PSv2
FAILs become N-A.

### Fixed — 2026-09-05 (F32 — Stage silently inherited a previous build's state)
`Stage-CyberRange.ps1` is documented as the FIRST-RUN bootstrapper, but it only
copies files: it never touched `C:\ProgramData\CyberRange\setup-state.json`, the
`CyberRangeSetup` resume task, or `READY.txt`. On a host that had been built
before, staging therefore handed off to an engine that either:
- announced **"Setup already completed (state = done). Nothing to do."** at Phase
  99 and exited — looking exactly as if Stage had done nothing; or
- **jumped straight into DC promotion or AD seeding** at the recorded phase, on a
  box the operator believed was starting from scratch.

Both present as "issues after the stage script". Now Stage detects prior state
(phase, READY.txt, resume task, and the ACL-locked/unreadable state file) and
STOPS before handing off, naming the three options:
- `-Continue` — resume at the recorded phase.
- `-Fresh` — clear bookkeeping only (state file, READY.txt, resume task) so the
  engine restarts at Phase 1. Loudly warns that this **does not unweaken the box**;
  logs and the manifest are kept as the audit trail.
- revert the VM snapshot — flagged as the recommended clean rebuild.

It also points at `Resume-CyberRange.ps1` for the "just continuing after a reboot"
case, and now prints the staged file count so a partial copy is visible.

### Verified — 2026-09-05 (Stage-CyberRange.ps1 operational check)
Static + behavioural verification, no build run:
- All 26 `.ps1`/`.psm1` files parse clean; `range.config.psd1` loads (16 keys).
- All 24 engine-referenced script paths exist at their staged locations.
- **Copy semantics tested**, fresh and re-stage: `Copy-Item -Path <src>\* -Recurse
  -Force` onto an existing tree produces no directory nesting and no duplication
  (5 files in, 5 files out, both passes). The suspected `scripts\scripts` re-stage
  bug does **not** occur.
- Stage→engine contract matches: both agree on `C:\CyberRange`; `-Force` is
  forwarded, `-Resume` correctly is not.
- `Assert-RangeSafety` does **not** block the current config (Confirmed=$true, no
  placeholder credentials remain).
- Known, unchanged behaviour: Stage never deletes files removed from the repo, so
  a renamed/retired script persists in `C:\CyberRange` until it is cleared.

### Fixed — 2026-09-05 (F8/F11 — ESC1 was non-functional; LDAP channel binding not downgraded)
First full end-to-end build succeeded (117 PASS). Remaining ESC1 defects fixed in
`scripts/dc/20-adcs-esc1.ps1`:
- **F8b — duplicate template OID.** The clone copied `msPKI-Cert-Template-OID` from
  the User template, so the CA couldn't resolve which template an OID meant. Now the
  OID is NOT copied; a unique OID is minted (a new `msPKI-Enterprise-Oid` under the
  forest OID container) and set on the template.
- **F8 — template not published.** Publishing is now robust and **verified**: wait
  for `CertSvc`, `Restart-Service CertSvc` so it picks up the new template/OID,
  publish via `Add-CATemplate` + `certutil -SetCATemplates`, then confirm the
  template appears in `certutil -CATemplates` (logs ERROR with the manual retry if not).
- **F8a — ESC1 rejected by the KDC.** Server 2025 defaults
  `Kdc\StrongCertificateBindingEnforcement` to 2 (Full Enforcement), which rejects a
  cert with no SID extension for PKINIT — so ESC1 never authenticates. Set to 1
  (Compatibility), which re-enables the classic ESC1 (a deliberate, gradable downgrade).
- **F11 — LDAP channel binding.** `NTDS\Parameters\LdapEnforceChannelBinding = 0` so
  LDAPS relay is exercisable (LDAP signing already handled in dc\40).

Verify on the next build with `certipy find -vulnerable` (RangeUserESC1 should show as ESC1).

### Fixed — 2026-09-05 (F31 — default password policy rejected the weak seeded accounts)
- **Phase 3 seeded users before the password policy was relaxed.** `dc\10-ad-users-roast.ps1`
  creates intentionally weak roast accounts, but it ran *before* `dc\40` (which relaxes
  the domain policy), so the DEFAULT policy (complexity on, min length 7, and "password
  must not contain the account name") rejected at least `helpdesk` / `Helpdesk@1` with
  "The password does not meet the length, complexity, or history requirement of the
  domain," failing Phase 3. Fix: relax the domain password policy (complexity off,
  min length 4) **at the start of Phase 3, before any seeding** (Setup), and also at
  the top of `dc\10` itself so it works when run standalone. `dc\40` still re-asserts
  the weak policy afterwards.

### Fixed — 2026-09-05 (F30 — the build did not auto-resume after the first reboot)
- **Root cause: the resume task hung on an interactive prompt.** The `-Resume`
  block gated its `Read-Host` on `[Environment]::UserInteractive`, which is
  **`True` for a scheduled task** (it only goes false for a service without
  desktop interaction), so the guard guarded nothing. At boot the SYSTEM task
  reached `Read-Host` and blocked forever on a console nobody can type into.
  `-ExecutionTimeLimit ([TimeSpan]::Zero)` meant nothing killed it, and because
  the task is `-MultipleInstances IgnoreNew`, the hung instance then suppressed
  every later trigger — so it blocked its own retries. The task fired correctly
  every time; it just never got past the prompt.
  **Fix:** gate on identity instead — `WindowsIdentity::GetCurrent().IsSystem`,
  plus the `UserInteractive` check as a secondary. Execution time limit is now a
  finite 3h so a future hang self-clears and the next boot can retry.

### Added — 2026-09-05
- `Resume-CyberRange.ps1` — manual resume entry point for when the build does not
  continue on its own. Reports where the build actually is (phase, resume-task
  state, last 15 log lines), **stops a stuck-Running resume task** (which would
  otherwise silently swallow `Start-ScheduledTask` under `IgnoreNew`), then hands
  off to the engine with `-Resume` in the current console. `-StatusOnly` reports
  and changes nothing; `-Force` passes through. Detects and explains the
  access-denied-on-`setup-state.json` case with the reclaim commands.
- `Write-ResumeHint` — the manual resume command is now printed immediately
  before every reboot, so it is the last thing on screen if auto-resume fails.

### Fixed — 2026-09-05 (F29: DC promotion prereq failure was opaque + caused a reboot loop)
- **`Install-ADDSForest` only throws a generic "Verification of prerequisites …
  failed"**, hiding the real cause. `scripts/dc/00-promote-dc.ps1` now runs
  `Test-ADDSForestInstallation` first and logs the **detailed** result, plus the two
  most common blockers explicitly: `PartOfDomain`/`Domain` (a new forest cannot be
  created on a domain-joined box) and a **pending reboot** (fails the prereq on its
  own).
- **Setup no longer reboot-loops on a promotion prereq failure.** Phase 2 captured
  the promote step's result: on failure it now **stops with the error** instead of
  forcing a reboot (a reboot does not clear a domain-join/config prereq). A genuine
  pending-reboot case is called out so the operator can reboot once and let the
  resume task retry.
- **Pre-flight refuses a domain-MEMBER host before weakening it.** Confirmed in the
  field: the box was already a member of `range.lab` (`PartOfDomain=True`, not a DC —
  a demoted/orphaned former DC captured in a snapshot), so a new-forest promotion
  can never succeed. Setup now throws at the very start when `DC.Enabled` and the
  host is a domain member (DomainRole < 4), naming the fix (`Add-Computer
  -WorkgroupName WORKGROUP -Force -Restart`, or use a clean standalone snapshot) —
  so it never weakens a box it cannot finish. The same **A0 "clean standalone base"
  gate** is now in the break-glass pre-flight (`00-break-glass.ps1`, BLOCKS a DC
  build on a domain member) and documented as Part A gate **A0** in
  `docs/VERIFICATION-SESSION.md`, with the standing rule to always revert to a
  clean never-joined snapshot, never one taken mid-/post-build.

### Fixed — 2026-09-05 (F28: DC couldn't reach its own AD -> Phase 3 wiped out; + test staleness)
- **F28 — ADWS unreachable because the DC didn't use itself for DNS.** On the real
  build the DC promoted, but `Get-ADDomain`/`Get-ADUser` failed with "Unable to find
  a default server with Active Directory Web Services running," so all seven Phase-3
  steps and the keeper's domain-account creation failed and `analyst`/`rangebreak`/
  hidden admins never got made. Root cause: the DC resolved DNS via the upstream/NAT
  resolver instead of itself, so it couldn't resolve its own SRV records. `Wait-ForAd`
  (Setup) and the keeper (`02-operator-keeper.ps1`) now **repair the DC DNS client to
  127.0.0.1** and start `NTDS,ADWS,DNS,Netlogon` before/while waiting. This is
  self-healing on the next boot.
- **Test staleness — Kerberos etypes.** `Test-RangeConfig.ps1` still expected the old
  `SupportedEncryptionTypes = 4`; the F26 fix correctly sets `28` (RC4+AES). The check
  is now bitwise: PASS on RC4+AES (`0x1C`), FAIL on the dangerous RC4-only (`0x4`),
  WARN if RC4 is absent.

### Fixed — 2026-09-05 (autologon needlessly withheld by a false-negative credential check)
- **`20-credential-exposure.ps1` disabled autologon even after setting the password.**
  It gated `AutoAdminLogon` solely on `PrincipalContext.ValidateCredentials`, which
  performs a NETWORK logon — routinely denied for a LOCAL account on a hardened/UAC
  box even when the password is correct (interactive login is unaffected). Result:
  the log said "Autologon NOT enabled: 'Administrator' did not validate" on a box
  whose Administrator password had just been set correctly. Now the SET is treated
  as authoritative: autologon is enabled when the password was set (or validated),
  and validation is informational. This is safe because `ForceAutoLogon` is never
  written — a wrong autologon password can only fall through to the logon screen,
  never loop. Only withheld if the SET itself failed. (Non-fatal either way; the box
  was always loginable via the account, `analyst`, or the accessibility shell.)

### Verified/Fixed — 2026-09-05 (audit of the Phase-3-failure + lockout work order)
Re-read every target file. Five of six items were **already present** from the
prior verification pass; one gap was closed. No duplication applied.
- **ALREADY DONE — item 1 (F26 Kerberos etypes):** `20-credential-exposure.ps1`
  uses `$RC4_PLUS_AES = 0x1C` (RC4+AES128+AES256) with the full rationale.
- **ALREADY DONE — item 2 (keeper on a DC):** `02-operator-keeper.ps1` writes a
  role-aware `C:\range-fix.cmd` (DC branch: repair etypes → clear domain lockout via
  `Set-ADDefaultDomainPasswordPolicy` → call `01-analyst-admin.ps1`, no `net user`),
  uses the AD cmdlet for DC lockout, and repairs the Kerberos value every boot when
  the AES bits (`0x18`) are clear.
- **ALREADY DONE — item 3 (Phase 4 order + non-destructive Protect-RangePath):**
  order confirmed by line (`Invoke-Analyst`→`READY.txt`→`Save-State` 99→
  `Protect-RangePath`); grant on the container only (no `/T`), children inherit, and
  a create+delete **write self-test** reverts + records `protect-path-REVERTED` if
  the dir is no longer writable.
- **ALREADY DONE — item 4 (AD-unreachable ≠ account-missing):** `Test-AdQueryable`
  + parser-safe `(Test-IsDomainController) -and -not (Test-AdQueryable)`; reports
  "ACTIVE DIRECTORY IS UNREACHABLE" instead of "does not exist".
- **ALREADY DONE (mostly) — item 5 (Wait-ForAd gate + -Force honesty):**
  `Wait-ForAd` returns `$true/$false`, prints ADWS/NTDS/DNS/Netlogon + nltest + DNS +
  Directory-Service diagnostics; Phase 3 gates on it via `Test-PhaseClean`;
  `$script:BuildHadFailures` set on `-Force` override.
- **NEWLY APPLIED — item 5 gap:** `READY.txt` **file** now carries a `STATUS:` line
  (`*** BUILD FINISHED WITH FAILURES -- NOT READY TO CLONE OR HAND OUT. ***` when
  forced past failures, else `build completed cleanly`). Previously only the console
  log distinguished this, so a `-Force` marker file looked hand-out-ready.

Verified: Setup parses clean; `Test-RangeConfig.ps1` runs end to end with a summary;
no ACLs loosened.

### Fixed — 2026-09-04 (F26 CRITICAL — root cause of the post-promotion lockout)
- **F26 — the KDC was pinned to RC4-only, breaking every domain logon.**
  `scripts/20-credential-exposure.ps1` set
  `...\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes = 4`. That
  value is an **allow-list**, and `0x4` is RC4-HMAC *only*, with AES128 (`0x8`)
  and AES256 (`0x10`) cleared. The orchestrator deliberately re-runs that script
  after promotion (Setup-CyberRange.ps1:353), so the finished DC supported only
  RC4 — which Server 2025 deprecates and disables by default. The KDC could not
  complete Kerberos exchanges, so **every domain logon failed, Administrator and
  `analyst` alike**, with no local SAM left to fall back on.

  This is the reported "locked out of everything after the 2nd reboot". It
  matches the symptom exactly: it cannot appear before promotion (local accounts
  use NTLM, not Kerberos), it defeats the operator keeper (the account was fine —
  the auth protocol was not), and it defeated `C:\range-fix.cmd` (every command in
  it targeted a local SAM the DC does not have).

  **Fix:** value is now `0x1C` (28) = RC4 + AES128 + AES256. Kerberoasting is
  unaffected — `dc/10` stamps `msDS-SupportedEncryptionTypes = 4` on the `svc_*`
  accounts individually, which is what forces the RC4 (etype 23 / `-m 13100`)
  service ticket. The weakness is scoped to the target principals instead of the
  whole KDC.

- **`C:\range-fix.cmd` was inert on a domain controller.** Every command
  (`net user`, `net localgroup`, `net accounts`) targets the local SAM. The card
  is now role-aware: on a DC it repairs the Kerberos etypes first, clears lockout
  via the Default Domain Policy, and calls the role-aware
  `01-analyst-admin.ps1` instead of `net user`.
- **Keeper's lockout disable was a silent no-op on a DC** — `net accounts` edits
  local-SAM policy. Now uses `Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 0`
  on a DC.
- **Keeper now re-checks the Kerberos etypes every boot** and repairs the value if
  AES has been cleared, so a re-run of a weakening script cannot re-create F26.

### Added — 2026-09-04
- `docs/SETUP-GUIDE.md` — full system overview (two-stage build, phase/reboot map,
  the three operator safety nets), prerequisites, step-by-step build, verification,
  and a symptom→cause lockout diagnostic table.

### Added — 2026-09-04 (operator keeper — self-healing login, ends the lockout cycle)
- **`scripts/02-operator-keeper.ps1` + `OperatorKeeper` toggle + a permanent
  SYSTEM-at-startup task (`CyberRangeOperatorKeeper`).** After repeated field
  lockouts (Administrator password rewritten by design, promotion wiping local
  accounts, phases/GPO drifting creds, and `analyst` becoming unusable), this keeps
  ONE account permanently good: on EVERY boot it re-asserts `analyst` (exists,
  enabled, unlocked, admin, password = `Config.Analyst.Password`, not hidden),
  role-aware (local vs domain; waits for AD on a DC). It also **disables account
  lockout** so a correct password is never rejected, and drops **`C:\range-fix.cmd`**
  — a short, TYPEABLE recovery command for the logon-screen SYSTEM shell, where
  clipboard paste does not work (a real limitation the operator hit). Unlike the
  temporary resume task, the keeper task is NOT removed at the end. Run once in
  Phase 1 and registered there. Logs to `C:\ProgramData\CyberRange\keeper.log`.

### Fixed — 2026-09-04 (first real-VM verification: HiveNightmare ACL + stale answer-key gate)
- **HiveNightmare ACLs never applied.** `icacls /grant BUILTIN\Users:(RX)` on
  SAM/SYSTEM/SECURITY was denied because Administrators lack WRITE_DAC on those
  hives (only SYSTEM has it), so `Test-RangeConfig` correctly reported "no Users
  ACE." `scripts/75-cve-repro.ps1` now runs `takeown` first, then grants the Users
  SID (S-1-5-32-545) read. (The VSS shadow-copy half already passed.)
- **`Test-RangeConfig` range-safety no longer FAILs on `C:\CyberRange`.** Same
  reconciliation as the break-glass pre-flight: only an open
  `C:\ProgramData\CyberRange` (the answer key) FAILs; an open `C:\CyberRange`
  (staged config, intentionally left inherited per F18) is now a WARN.

### Fixed — 2026-09-04 (break-glass/analyst local account creation blocked EVERY build)
- **`New-LocalUser -Description` has a 48-character limit; ours was 72**, so
  `New-LocalUser` threw, the local break-glass (`rangebreak`) and analyst accounts
  were never created, AUTH VALIDATION failed, and F21 blocked the build at Phase 1.
  This was the actual reason "the users still aren't created / I can't log in."
  Shortened both descriptions (`scripts/00-break-glass.ps1`, `scripts/01-analyst-admin.ps1`)
  to <=48 chars. (`New-ADUser` on a DC has no such limit; the standalone/Phase-1
  local branch is where it bit.) Verified `New-LocalUser -WhatIf` accepts the new
  strings.
- **Pre-flight no longer hard-fails on a readable `C:\CyberRange`.** We deliberately
  stopped locking the staged tree (to end the access-denied lockouts; the operator
  is admin anyway, F18). The break-glass answer-key gate now FAILs only on an open
  `C:\ProgramData\CyberRange` (the real answer key), and downgrades an open
  `C:\CyberRange` to WARN, so the pre-flight can reach PASS.

### Added — 2026-09-04 (accessibility SYSTEM shell — operator break-glass + T1546 artifact)
- **`scripts/05-accessibility-shell.ps1`**, applied in Phase 1 (toggle
  `AccessibilityShell`, default on). Sets an Image File Execution Options
  `Debugger` on `utilman.exe` and `sethc.exe` so that at the LOGON SCREEN the
  Ease-of-Access button / Win+U, or pressing Shift x5, opens **cmd.exe as SYSTEM**.
  Dual purpose: (1) a guaranteed no-password recovery path so the operator can
  never be fully locked out again — create/reset any account from that shell — and
  (2) a gradable persistence artifact (MITRE T1546.008 / T1546.012). Chosen over
  replacing the binaries because IFEO is registry-only: no WRP fight, it survives
  DC promotion (HKLM, not the SAM), and it is reversible by deleting the two
  Debugger values. `Test-RangeConfig.ps1` verifies both are set.

### Fixed — 2026-09-04 (resume deadlock on a DC — reverted to SYSTEM-at-startup)
- **The visible at-logon resume deadlocked on a DC and locked the operator out.**
  Promotion (Phase 2) destroys the local SAM, so the local `analyst` / break-glass
  accounts are gone and are not recreated as DOMAIN accounts until Phase 3 — but the
  at-logon resume could not run Phase 3 until someone logged in, and the account to
  log in with did not exist yet. Reverted `Register-ResumeTask` to **SYSTEM at
  startup**, which runs Phase 3 unattended (SYSTEM on a DC can create domain
  accounts) so `analyst` exists by the time READY.txt appears. The `-Resume` ENTER
  prompt is kept but only shows for a manual, interactive `-Resume` run (guarded by
  `[Environment]::UserInteractive`); the SYSTEM task auto-continues. Net: the build
  no longer needs any login to complete, and account creation never depends on one.

### Changed — 2026-09-04 (visible, prompt-driven resume after reboot) [SUPERSEDED same day by the fix above]
- **The post-reboot resume is now visible and asks before continuing.** It was a
  hidden SYSTEM task at startup, so after Phase 1 rebooted the build appeared to do
  nothing ("setup not working after stage") with no way to see or drive it.
  `Register-ResumeTask` now creates a task that fires **at the logon of any
  administrator** (`BUILTIN\Administrators`, `RunLevel Highest`), opens a **visible,
  elevated** PowerShell (`-NoExit`, no `-WindowStyle Hidden`), and the engine
  **prompts "Press ENTER to continue"** when it runs with `-Resume`. Benefits:
  (1) the operator sees each phase resume; (2) triggering on the group rather than a
  fixed username survives the local→domain Administrator change at promotion; and
  (3) if autologon ever fails, simply logging in as `analyst` (an admin) fires the
  resume. `-MultipleInstances IgnoreNew` prevents duplicate windows. Manual
  fallback if a prompt never appears: log in as `analyst` and run
  `C:\CyberRange\Setup-CyberRange.ps1 -Resume`.

### Added — 2026-09-04 (stable operator admin: "analyst")
- **A standing admin account the build never rewrites.** Repeated iterations hit
  the operator being locked out because the build *intentionally* sets the built-in
  Administrator's password to `LocalAdminAutoLogonPass` (the exposed-credential
  lesson), so Administrator is not a stable login. Added a config `Analyst` block
  (`analyst` / `bb123#123`) and `scripts/01-analyst-admin.ps1` — a standalone,
  role-aware provisioner: LOCAL Administrators on a non-DC, Domain Admins on a DC,
  not hidden from the sign-in screen, password-never-expires, and it validates that
  the account authenticates. The engine calls it in **Phase 1** (local,
  pre-weakening), **Phase 3** (re-created as a domain admin after promotion, since
  the local SAM is gone), and **Phase 4** (final assert) — so it is guaranteed
  present after the build regardless of what happened. `READY.txt` now tells the
  operator to log in as `analyst`, and `Test-RangeConfig.ps1` verifies it exists
  with admin rights. To create it on an already-built box without a rebuild:
  `.\scripts\01-analyst-admin.ps1` (elevated).

### Changed — 2026-09-04 (Test-RangeConfig.ps1: operational verification + control mapping)
Audit found the checker was verifying **declared** state (a registry value) where
**operational** state was available, and had gaps against the build. Now:

- **Live-state probes added** where the OS exposes the truth, each tagged `[live]`:
  - **LSASS is opened for `PROCESS_VM_READ`** via P/Invoke — the operational proof
    behind `RunAsPPL`. A registry `0` says nothing if PPL is UEFI-locked or the box
    has not rebooted. Corroborated with the Wininit event-12 boot record.
  - `Win32_TSGeneralSetting` for the RDP listener's real NLA/security-layer state,
    plus a 3389 listener check.
  - `Get-ExecutionPolicy` effective policy, not just the policy key.
  - `Get-WinEvent -ListLog` channel sizes — the build also calls `wevtutil`, so the
    registry and the channel can disagree.
  - `Get-Service` StartType/Status for `wuauserv`/`WaaSMedicSvc`/`UsoSvc`;
    `WaaSMedicSvc` exists specifically to undo the registry value.
  - VBS running state, WinRM CredSSP + `TrustedHosts`, PSv2 optional feature,
    TFTP, `Get-SmbShareAccess` for Everyone:Full, `Win32_ShadowCopy` for the
    HiveNightmare prerequisite, AD CS `CertSvc`, `certutil -CATemplates` for actual
    template publication.
- **Coverage gaps closed:** null sessions (`RestrictNullSessAccess`,
  `NullSessionPipes`, `NullSessionShares`), `ProcessCreationIncludeCmdLine`,
  transcription, `RunAsPPLBoot`, HVCI, RDP `SecurityLayer`/`fPromptForPassword`,
  WinRM CredSSP/TrustedHosts, Winlogon `Shell` hijack, startup-folder payload,
  `SYSTEM`/`SECURITY` hive ACLs (only `SAM` was checked), beacon containment (F6),
  answer-key ACLs (F3), break-glass sign-in visibility, GenericAll on Domain
  Admins, `ms-DS-MachineAccountQuota`, lockout threshold, password-in-description,
  Account/Server Operators membership, and ESC1 sub-conditions (RA-signature,
  manager approval, client-auth EKU, **duplicate template OID**).
- **F8–F11 are now checked**, so the report can no longer claim ESC1 works on a
  host where it cannot: `Kdc\StrongCertificateBindingEnforcement` (unset/2 ⇒ ESC1
  FAILs), `KDC\DefaultDomainSupportedEncTypes` (RC4 bit), and
  `NTDS\Parameters\LDAPServerIntegrity` + `LdapEnforceChannelBinding`.
- **`Control` and `Probe` fields added** to every result (NIST SP 800-53 Rev.5 /
  CIS Controls v8.1, per docs/GRC-CONTROL-MAP.md; `Probe` = `live` or `reg`). This
  is the start of gap **G4** — the output is now a scoring baseline, not just a
  build check. `-ShowControl` renders mappings inline; the summary counts live vs
  registry-only probes and lists failures with their controls.

### Fixed — 2026-09-04 (Test-RangeConfig.ps1 defects found while auditing)
- **Firewall check passed when only ONE profile was disabled** (`$off.Count -ge 1`).
  The build disables all profiles; a partially re-enabled firewall reported PASS.
  Now FAILs and names the profiles still enabled.
- **Two `Add-Result` calls used unparenthesised string concatenation** as a command
  argument, so `+` and its operands bound as extra positional parameters instead of
  building one string (answer-key ACL and unconstrained-delegation results).
- **`Get-RegVal` threw and caught ~100 errors per run** on an unbuilt host, filling
  `$Error` with noise that looked like a crash. Rewritten to probe without throwing
  (101 → 24 residual records, the rest being benign "not found" from
  `Get-ScheduledTask`/`Get-Service` on absent range objects).
- **`Get-WindowsFeature` crashed on client SKUs** — `-ErrorAction` cannot suppress
  `CommandNotFoundException`. Guarded with a `Test-HasCommand` helper, as is
  `Get-LocalUser` (which wrote an error record per missing account).
- Reversible-encryption and unconstrained-delegation queries moved to explicit
  `userAccountControl` LDAP bit filters; SPN query moved to `-LDAPFilter`.
- Duplicate `Beacon payload dropped` rows now name the file; dead `$counts`
  variable removed; `N-A` added to the summary line.

Verified by executing the script end to end on a non-range host: parses clean,
102 results, JSON/CSV round-trip, and the expected near-total FAIL as a negative
control. **Not yet run against a built Server 2025 range.**

### Fixed — 2026-09-04 (F25 critical + WP3 safety gates F19–F21)
- **F25 CRITICAL — staged tree could be left world-readable.** In the field the
  operator ran `takeown` + `icacls "C:\CyberRange" /grant Everyone:(OI)(CI)F` to
  get a `Set-*` script to run, which re-opened F3 (and worse: added write) —
  exposing the staged `range.config.psd1` (every operator secret) and letting any
  account tamper with the build. Root cause was **running non-elevated** (UAC
  filters the Administrators token; `EnableLUA=0` needs a reboot), not a missing
  grant. Fixes: `Protect-RangePath` and the staging step now `/setowner
  Administrators`, `/inheritance:r`, `/grant:r SYSTEM+Administrators`, and
  **explicitly `/remove:g` Everyone (S-1-1-0), Authenticated Users (S-1-5-11) and
  Users (S-1-5-32-545)** — so a re-run *repairs* a directory someone loosened. The
  break-glass pre-flight already FAILs when `C:\CyberRange` or the ProgramData tree
  is readable by non-admins. Correct way to get unstuck is to **run elevated**
  (and `Unblock-File`), never `Everyone:F`.
- **F20 — placeholder credentials now block the build.** `Assert-RangeSafety`
  refuses to run while any of `LocalAdminAutoLogonPass`, `DC.SafeModePassword`,
  `BreakGlass.Password`, `HiddenAdminPassword` is a shipped placeholder (list held
  in the module, not the config). Override for off-network dry runs only:
  `-AllowPlaceholderCredentials` (Setup: `-Force`). **Action: the shipped config
  still has placeholders, so the next build will refuse until they are changed.**
- **F21 — break-glass failure is now fatal.** `Invoke-BreakGlass` verifies the
  recovery account actually exists after provisioning; if not, it increments the
  phase-failure count so `Test-PhaseClean` blocks the Phase 1 reboot (override with
  `-Force`). Previously it logged an error and weakened the box anyway — the exact
  no-recovery window that caused the lockout.
- **F19 (partial) — `READY.txt` no longer points the blue team at the answer key.**
  Removed the "Blue team: the manifest lists every change" line and the manifest
  path; it now names only the build log and the operator runbook. The full
  manifest/answer-key file split (`-Secret` routing) remains open under WP3.
- **F25 follow-ups (same day, after a field retest).** (1) Staging no longer locks
  `C:\CyberRange` *before* relaunching from it — that left the relaunched process
  unable to read its own script ("Access to the path ... is denied"). The lock now
  happens inside the local instance *after* relaunch (`Protect-RangePath -Path
  $LocalRoot`), and staging first `/reset`s any mangled ACL left by a prior manual
  workaround. (2) The F20 placeholder list no longer includes `CrazySnow2024*`
  (HiddenAdminPassword) — that is intended seeded loot, not a change-me
  placeholder, and must not block the build.

### Changed — 2026-09-04 (two-stage setup)
- **Split staging from the build engine.** New `Stage-CyberRange.ps1` (Stage 1) is
  the first-run script: it heals any stale `C:\CyberRange` ACL, copies the repo
  there, strips mark-of-the-web, and hands off to `Setup-CyberRange.ps1` (the
  engine, Stage 2) from the local copy. The engine no longer self-stages/relaunches
  and now refuses to run from anywhere but `C:\CyberRange`, pointing the operator at
  the stager. This removes the lock-then-reread relaunch hazard entirely and makes
  the boot-time SYSTEM resume task's local-copy requirement explicit. Operator
  command is now `.\Stage-CyberRange.ps1` (README / HANDOFF / BREAK-GLASS updated).
- **Stopped ACL-locking the staged tree (`C:\CyberRange`).** Repeated field
  "access denied" failures all traced to `Protect-RangePath` locking the staged
  code+config to SYSTEM+Administrators, which then denied a re-run or a
  non-elevated child. The engine no longer locks `$LocalRoot`; it inherits normal
  permissions. The sensitive artifact — the change manifest / answer key under
  `C:\ProgramData\CyberRange` — is still locked by `Initialize-RangeContext`. The
  staged `range.config.psd1` is now readable by local users, which is acceptable:
  the operator is Administrator on a built box anyway (F18), and off-boxing the
  answer key is owned by WP2/WP3. The stager `takeown`+`/reset`s any previously
  locked `C:\CyberRange` once, to clear the leftover from earlier runs.

### Added — 2026-09-04
- `Test-RangeConfig.ps1` — standalone, read-only post-build checker. Verifies every
  machine-level misconfiguration (and, on a DC, the AD scenarios: Kerberoast/AS-REP
  fodder, ESC1 template, delegation, weak password policy, GPP cpassword) plus the
  break-glass and hidden-admin accounts, reporting PASS/FAIL/WARN/N-A with a summary
  and optional `-Format Csv|Json -Out`. It is the executable form of the Part B
  matrix in `docs/VERIFICATION-SESSION.md`; the register-driven
  `Test-RangeCompliance.ps1` (WP1) will later generalize it. No RangeCommon
  dependency; changes nothing; exit code always 0.

### Decided — design session 2026-09-03 (documentation only; no code changed)
- **Topology (closes the G1 question).** One VM per participant, all on a **shared
  range LAN** with no route to campus or the internet. Lateral-movement targets are
  **other participants' VMs**, so relay, NTLM downgrade, WinRM/RDP movement and
  delegation coercion are exercisable rather than inert.
- **Scoring baseline.** CIS Microsoft Windows Server Benchmark governs blue-team
  grading; NIST SP 800-63B is a documented deviation taught as the framework
  conflict. The exact benchmark release is still to be pinned.
- **Instructor infrastructure.** A **range-administrator box sits on the same
  subnet**: answer-key store, log collector, offline package source, scoring host,
  and the red-cell C2 delivering **implants for initial access**. This closes G3
  (nowhere for logs to go) and gives F13/F18/F22 real destinations.
- **First boot.** Range administrators perform first boot and personalization
  before the student receives the VM — which is what makes WP2's
  master-secret-never-touches-the-VM derivation model viable.
- **First build task.** The finding register + `Test-RangeCompliance.ps1` (WP1).

### Added
- `docs/IMPROVEMENT-PLAN.md` — the design session's output: decisions D1–D5,
  seven new findings (F16–F22), and 13 sequenced work packages with specs and
  acceptance criteria, written so another session can implement them without
  re-deriving the reasoning.

### Known issues (new — F16–F22, none implemented)
- **F16 CRITICAL.** The golden image is cloned **after** DC promotion, so every
  participant VM shares `krbtgt`, the domain SID and every NT hash. On the shared
  LAN a golden ticket or pass-the-hash from one box owns every other box. Fix is
  structural: cut the image before promotion and let each clone promote its own
  forest at first boot (WP2). **Do not distribute an image until this lands.**
- **F17 HIGH.** Nothing renames the computer, and every clone claims `range.lab` /
  `RANGE` — NetBIOS and DNS collisions on one segment, ambiguous attack targets.
- **F18 HIGH.** Autologon makes the participant a Domain Admin, so the F3 ACL
  (SYSTEM + Administrators) does not keep them out of the answer key. Every seeded
  password, DSRM, break-glass and hidden-admin credential is readable on their own
  box — and, per F16/F17, valid on every peer.
- **F19 HIGH.** `READY.txt` tells the blue team to read the manifest, which is both
  ACL-restricted and the answer key. Split change manifest from answer key.
- **F20 MEDIUM.** Placeholder credentials are gated by documentation only;
  `Assert-RangeSafety` should refuse to build while they are present.
- **F21 MEDIUM.** Break-glass provisioning failure is non-fatal, so Phase 1 can
  still weaken the box and reboot with no recovery account — the exact condition
  F2 was raised to prevent.
- **F22 MEDIUM.** The on-box register/compliance script is writable by the
  participant, so scoring must run from a copy the participant never controlled.
- **F23 HIGH.** The administrator box is the crown jewel on a subnet of hostile,
  unfirewalled hosts — it holds answer keys, log collection, scoring, the package
  share and live C2, one hop from thirty machines whose owners are Domain Admins
  being taught lateral movement. It must be explicitly out of scope, firewalled,
  and must **not** hold the clone master secret. All collection is **pull, never
  push**, so no admin credential ever lands on a student VM.
- **F24 MEDIUM.** Seeded persistence and live red-cell implants are currently
  indistinguishable, so "I found and removed a beacon" cannot be adjudicated.
  Needs distinct naming, locations and beacon destinations, plus a red cell that
  logs its own actions against the same timeline.

### Fixed — verification findings F1–F7 applied
- **F1 — the lockout triad.** `scripts/20-credential-exposure.ps1` now (1) SETS
  `LocalAdminAutoLogonUser`'s password to `LocalAdminAutoLogonPass` before
  touching autologon, so the credential and the registry value cannot diverge;
  (2) writes **`DefaultDomainName`** (`.` standalone, `DC.NetbiosName` on a DC);
  (3) **never writes `ForceAutoLogon`** and strips it if an earlier run left it.
  `AutoAdminLogon` is only set to `1` after the credential is validated with
  `PrincipalContext.ValidateCredentials`; otherwise it is set to `0` and the run
  logs an error. The teaching artifact — cleartext `DefaultPassword` in the
  registry — is unchanged. Phase 3 re-runs the script post-promotion because
  `DefaultDomainName` differs once the local SAM is gone.
- **F2 — break-glass before weakening.** `Setup-CyberRange.ps1` calls
  `scripts/00-break-glass.ps1 -Apply -FromBuild` as the first action of Phase 1,
  and again at the start of Phase 3 on a DC (promotion destroys the local
  account). Driven by the new `BreakGlass` config block, so it runs unattended.
  `Categories.HiddenAccounts` is now actually read (was dead config).
- **F3 — answer key locked down.** New `Protect-RangePath` helper in
  `RangeCommon.psm1`; applied to `C:\ProgramData\CyberRange` at log
  initialization, to `C:\CyberRange` at staging, and re-asserted in Phase 4.
  Strips inheritance, grants SYSTEM + Administrators only.
- **F4 — Defender toggles actually run.** `Set-MpPreference @{ ... }` (positional
  hashtable, always threw) replaced with a variable splat.
- **F5 — `Invoke-RangeBuild.ps1` written.** The manual/partial orchestrator the
  docs referenced in six places now exists: `-Only`, `-SkipDC`, `-List`, no
  reboots, validates category names before applying anything, and warns when no
  break-glass account is present.
- **F6 — beacon containment.** `BeaconHost` `10.0.2.15` → `192.0.2.1`. The old
  value was RFC 1918 / the VirtualBox NAT guest address, not RFC 5737 as its own
  comment claimed.
- **F7 — failed phases no longer advance.** `Invoke-Step` returns success and
  increments a per-phase failure count; `Test-PhaseClean` blocks the phase
  transition (and the reboot) unless `-Force` is passed.

### Added
- `scripts/00-break-glass.ps1` — standalone (no `RangeCommon` dependency)
  pre-flight + recovery tool. Default mode is read-only and exits non-zero if any
  Part A gate fails; `-Apply` provisions and **validates** a visible break-glass
  administrator (local, or domain on a DC); `-RepairAutologon` clears a forced
  autologon loop. Also checks beacon containment and answer-key ACLs.
- `docs/BREAK-GLASS.md` — six-layer recovery runbook (snapshot → break-glass →
  seeded admins → DSRM → offline Windows RE → rebuild) and the pre-build drill.
- `docs/VERIFICATION-REPORT-2026-09-03.md` — static verification pass, 15 ranked
  findings.
- `docs/IMAGE-DESIGN-PROMPTS.md` — prompt library for producing an image design
  document, structured as **layers x hosts** (L0 base image … L11 operator plane).
  Phase 0 prompts force the topology decision that gap G1 turns on.
- `docs/GRC-CONTROL-MAP.md` — every misconfiguration mapped to NIST SP 800-53
  Rev. 5, CIS Controls v8.1, CIS Benchmark / DISA STIG settings, and the NSA/ACSC
  AD compromise guidance; plus 11 ranked scenario gaps.

### Known issues (open)
- **Nothing is verified on hardware.** F1-F7 are fixed in source but **no
  end-to-end build has run on a Server 2025 VM since**. Every claim in this
  release is static-review-only. Run the Part B matrix before trusting any of it.
- **Several techniques are expected to be inert on Server 2025** and must be
  re-tested rather than assumed: ESC1 (strong certificate binding enforcement +
  a duplicated template OID), NTLMv1 (removed in 24H2/2025), RC4 Kerberos (never
  enabled domain-wide), LDAP signing/channel binding (never downgraded).
  Findings F8-F11.
- **`dc/10` is not idempotent for SPNs** - a Phase-3 retry against existing users
  silently produces zero Kerberoast targets. Finding F12.
- **SNMP install fails on an isolated box and reports success.** Finding F13.
- **Placeholder credentials still shipped**: `LocalAdminAutoLogonPass = 'Password!'`,
  `DC.SafeModePassword = 'S@feM0de-ChangeMe!'`, `BreakGlass.Password =
  'ChangeMe-BreakGlass!2026'`. The F1 fix means `LocalAdminAutoLogonPass`
  **becomes** the Administrator password - set it deliberately.

### Known issues (closed this session)
Findings F1-F7, detailed under **Fixed** above. Full context in
[docs/VERIFICATION-REPORT-2026-09-03.md](docs/VERIFICATION-REPORT-2026-09-03.md).

## 2026-09-03 (verification session)

### Added
- Break-glass tooling and the four documents listed under **[Unreleased] → Added**.

### Changed
- Static verification pass over the whole repo (15 findings), then F1-F7 applied
  at the operator's direction. F8-F15 remain reported-only and are listed under
  **Known issues (open)**.

## 2026-09-03

### Added
- `Setup-CyberRange.ps1` — one-shot orchestrator: stages files to `C:\CyberRange`,
  runs all phases, reboots and auto-resumes via a SYSTEM scheduled task
  (`CyberRangeSetup`), drops `C:\ProgramData\CyberRange\READY.txt` when done.
- `scripts/dc/50-hidden-domain-admins.ps1` — hidden admins as **domain** accounts
  (local ones don't survive DC promotion).
- `CHANGELOG.md`, `HANDOFF.md`, `docs/VERIFICATION-SESSION.md` — project workflow docs.

### Changed
- README: one-shot `Setup-CyberRange.ps1` is now the documented primary path;
  `Invoke-RangeBuild.ps1` retained for manual/partial runs.
- `BeaconHost` guidance rewritten for standalone per-participant VMs (reserved,
  non-routable target; nothing needs to listen).

### Fixed
- `Write-RangeLog`: `$Level` had no `Position`, so every `Write-RangeLog 'msg' 'WARN'`
  call failed ("A positional parameter cannot be found that accepts argument 'WARN'").
  Gave `$Level` `Position = 1`. This had aborted the whole build at the safety guard.
- `Set-RegValue`: now tolerates ACL-/Tamper-Protection-locked keys — logs a
  `set-reg-BLOCKED` manifest row and continues instead of throwing (e.g. the
  Defender `Features\TamperProtection` value on 2025).
- `scripts/dc/00-promote-dc.ps1`: corrected `Import-Module` target to `ADDSDeployment`,
  captures the `Install-WindowsFeature` result, installs `RSAT-ADDS` if the module
  is missing, and stops cleanly with a "reboot then re-run" message when tools
  need a restart.
- Logging hardened against transient file locks via `Add-RangeFileLine` (retry).

## 2026-09-02

### Added
- Initial modular framework: `modules/RangeCommon.psm1` (logging, CSV manifest,
  safety guard, idempotent reg/native helpers), `config/range.config.psd1`,
  `Invoke-RangeBuild.ps1`.
- Standalone misconfiguration categories `scripts/10`–`90` and `scripts/75-cve-repro.ps1`.
- Domain Controller scenarios `scripts/dc/00`–`40` (promote, Kerberoast/AS-REP
  seeding, AD CS ESC1 template, weak ACLs / delegation, GPP cpassword + weak policy).
- `README.md` with the 2019→2025 change notes.
