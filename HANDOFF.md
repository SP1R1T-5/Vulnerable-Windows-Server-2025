# Handoff / Progress Tracker

Living status doc for the Windows Server 2025 cyber-range builder. Keep it current:
when you finish a work session, update **Current status**, **Known issues**, and
**Next steps**, and add a line to [CHANGELOG.md](CHANGELOG.md).

_Last updated: 2026-09-07 (restructured into three steps, then built and troubleshot on hardware)_

> **2026-09-07 - RESTRUCTURE. Read this before touching anything.**
>
> **Three entry points, and the build order is reversed.**
>
> ```powershell
> .\Stage-CyberRange.ps1     # 1. Build the domain.      Nothing is weakened.
> .\Setup-CyberRange.ps1     # 2. Apply the misconfigs.  This is the range.
> .\Test-RangeConfig.ps1     # 3. Verify.  -Repair fixes drift.  Optional.
> .\Reset-CyberRange.ps1     #    Teardown, kept separate.
> ```
>
> - **Structure first, break it second.** The DC is now promoted while the box is
>   still healthy; nothing is weakened until Setup. The old order (weaken, then
>   promote) is what made promotion fragile and produced the field lockouts.
> - **No clone path.** Each VM is built from scratch on fresh Server 2025.
>   `Initialize-RangeClone.ps1`, `Get-RangeCloneSecret.ps1` and `-Mode Image` are
>   gone. **F16 and F17 are closed by construction** - no clone, no shared
>   `krbtgt` or domain SID.
> - **Every misconfiguration is declared once** in `modules\RangeControls.psm1`
>   (125 controls). Setup applies from it, Test checks against it, Reset reverts
>   from it. Add or change a control in that one file.
> - **`scripts\` went from 21 files to 10**, all role-named, no numeric prefixes.
>   `Resume-CyberRange.ps1` and `Repair-RangeConfig.ps1` are gone (Stage resumes
>   itself; repair is `Test-RangeConfig.ps1 -Repair`).
> - **Credentials set.** `DC.SafeModePassword` and `Analyst.Password` were still
>   shipped defaults; both are now random 24-char secrets. Recorded off-box by the
>   operator - they are NOT recoverable from this repo.
> - **BUILT AND TROUBLESHOT ON HARDWARE 2026-09-07** (`WIN-UGR8U7OFA11`). Three
>   findings came out of that run and are fixed in the tree: **F39** (a `Disabled`
>   ADWS silently sank every AD step - `Start-Service` cannot start a disabled
>   service, and `SilentlyContinue` hid it), **F41** (the AD CS role and FS-SMB1
>   are `InstallPending` until a reboot, so Setup could never configure the CA in
>   the same session - both are now pre-installed in Stage, ahead of its existing
>   reboot), and **F40** (`EnableSecuritySignature=0` is not settable on a DC at
>   all; now N-A, and it was never the relay-relevant toggle). Full symptoms and
>   recovery steps are in **[docs/USER-GUIDE.md](docs/USER-GUIDE.md) section 9**.
> - **`Test-RangeConfig.ps1 -Next`** prints the one command to run next, chosen
>   from the STAGED/READY markers and the current results. Start there when
>   picking the build back up.

---

## Purpose

Provision an intentionally vulnerable Windows Server 2025 **Domain Controller**
for a university red-vs-blue lab (config management, vuln management, IR, and
collegiate-competition tradecraft). **One VM per participant, each built from
scratch** on fresh Server 2025. Educational use only.

**Topology (decided 2026-09-03, design session):** one VM per participant, all on
a **shared range LAN** with no route to campus or the internet. Participants'
lateral-movement targets are **each other's VMs** — so relay, NTLM downgrade,
WinRM/RDP movement and delegation coercion are live, not inert. A
**range-administrator box sits on the same subnet**: it is the answer-key store,
log collector, offline package source, scoring host, and the **red-cell C2 that
delivers implants for initial access**. **Range administrators perform first boot
and personalization** before a student receives the VM.

That makes the range **multi-tenant with live offensive infrastructure**; see
findings **F16–F24** in [docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md).
**F16 and F17 are now closed by construction** — building each VM from scratch
means there is no clone, and therefore no shared `krbtgt` or domain SID.

**Scoring baseline (same session):** CIS Microsoft Windows Server Benchmark,
pinned release. NIST SP 800-63B is a documented deviation, taught as the framework
conflict, not used for grading.

## Current status

> ### PHASE 1 VERIFIED ON HARDWARE 2026-09-06 (pre-restructure)
> `WIN-UGR8U7OFA11`, Server 2025, promoted DC for `range.lab`.
> **`Test-RangeConfig.ps1`: 0 FAIL.** Every attack path confirmed live: ESC1
> published and enrollable, Kerberoast with RC4-stamped SPNs, AS-REP roasting,
> DCSync, GenericAll on Domain Admins, constrained + unconstrained delegation,
> MAQ=10, GPP cpassword in SYSVOL, SMB1 with signing off, LSASS confirmed
> dumpable via OpenProcess, and the full persistence set.
>
> **That result predates the 2026-09-07 restructure.** No control VALUE changed,
> so re-verification is a regression check rather than new verification - but it
> has not been run yet.

- **Entry points:** `Stage-CyberRange.ps1` (structure) -> `Setup-CyberRange.ps1`
  (misconfigurations) -> `Test-RangeConfig.ps1` (verify, `-Repair` to fix drift),
  plus `Reset-CyberRange.ps1` for teardown.
- **Control table:** `modules/RangeControls.psm1`, 125 controls, one definition
  each. Setup applies from it, Test checks against it, Reset reverts from it.
- **Helpers:** 10 role-named files under `scripts/`, no numeric prefixes, no
  `scripts/dc/` directory.
- **Teardown:** `Reset-CyberRange.ps1` undoes the range in place (dry run by
  default). It cannot undo promotion, exposed credentials, or missed patches.
- **AD scenarios:** ESC1 was broken as written (F8/F34: duplicate template OID,
  then a V1/V2 schema hybrid the CA rejected) and is now published and enrollable.
- **Verification:** the 2026-09-03 static review
  ([archived](docs/archive/VERIFICATION-REPORT-2026-09-03.md)) is history: F1-F15
  are closed or documented deviations, and F26-F38 were found and closed during
  the hardware bring-up (see CHANGELOG).
- **Recovery:** one operator account (`analyst`), provisioned by the pre-flight
  before the domain is built, re-created as a domain admin after promotion, and
  re-asserted on every boot by `CyberRangeOperatorKeeper`. Seven documented
  recovery layers in [docs/BREAK-GLASS.md](docs/BREAK-GLASS.md).
- **GRC:** misconfigurations map to published controls in
  [docs/GRC-CONTROL-MAP.md](docs/GRC-CONTROL-MAP.md). The biggest remaining gap is
  that there is no measurable baseline, so blue-team remediation cannot be scored.
- **Design:** [docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md) - WP1, WP3,
  WP5, WP11 remain unimplemented. WP2 is obsolete: the clone model it specified
  was removed, and F16/F17 are closed by building each VM from scratch instead.

## How to run

Elevated PowerShell on a fresh, snapshotted, standalone Server 2025 VM:

```powershell
.\Stage-CyberRange.ps1     # builds the domain; reboots once and resumes itself
.\Setup-CyberRange.ps1     # applies the misconfigurations; reboots at the end
.\Test-RangeConfig.ps1     # verifies; -Repair fixes drift
```

Stage offers to run Setup, and Setup offers to run Test. `-Auto` on Stage chains
all three without prompting. Markers: `STAGED.txt`, then `READY.txt`, both under
`C:\ProgramData\CyberRange`. The full change list is the manifest CSV in
`C:\ProgramData\CyberRange\logs\`.

**Always snapshot the VM before running.**

## Known issues / risks

### 0. Phase-3-failure + post-promotion lockout work order (AUDITED 2026-09-05)
The 6-item work order from the real-build log (host WIN-UGR8U7OFA11) is now fully
in the tree: **F26 RC4-only KDC** (etypes = `0x1C`), **DC-aware operator keeper +
`range-fix.cmd`**, **non-destructive `Protect-RangePath` with a write self-test +
Phase-4 ordering** (state file written before the ACL lock), **AD-unreachable
reported as such (not "account missing")**, and **`Wait-ForAd` as a hard Phase-3
gate**. Five were already applied by the prior pass; the one gap closed this session
is the **`READY.txt` file now stating `BUILD FINISHED WITH FAILURES`** on a `-Force`
run. Still unproven on hardware — re-build on a clean **standalone (not
domain-joined)** VM and run `Test-RangeConfig.ps1`.

### 1. Operator lockout (FIXED IN SOURCE — unproven on hardware)
Three contributing causes, all now addressed. Detail in
[docs/VERIFICATION-REPORT-2026-09-03.md](docs/archive/VERIFICATION-REPORT-2026-09-03.md)
F1/F2; recovery in [docs/BREAK-GLASS.md](docs/BREAK-GLASS.md).

- **Symptom was:** after a build, Administrator can't log in. Backup admins
  (`svc-backup` … `CrazySnow2024*`) also failed.
- **Cause 1 — password mismatch.** Nothing set the Administrator password, so
  `ForceAutoLogon=1` with a stale `DefaultPassword` looped forever.
  → **Fixed:** `20-credential-exposure.ps1` now sets the account password to
  `LocalAdminAutoLogonPass` first, validates it, and only then enables autologon.
- **Cause 2 — `DefaultDomainName` never set.** After promotion the account is
  `RANGE\Administrator`, so an unqualified `DefaultUserName` failed regardless of
  the password. → **Fixed:** written as `.` standalone / `DC.NetbiosName` on a DC,
  and Phase 3 re-runs the script post-promotion to correct it.
- **Cause 3 — no recovery account in the dangerous window.** The `*-backup` admins
  arrive in Phase 3; the window opens at the Phase 1 reboot. → **Fixed:**
  break-glass provisioning is the first action of Phase 1, repeated in Phase 3 on
  a DC. `Categories.HiddenAccounts` is now actually read.
- **`ForceAutoLogon` is never written** and is stripped if an earlier run left it.
- **Still to prove:** none of this has run on a Server 2025 VM.

### 1b. Answer key world-readable (FIXED — F3)
`C:\ProgramData` and `C:\` grant `BUILTIN\Users: ReadAndExecute` by inheritance,
so the manifest (every seeded password in cleartext) and the staged config were
readable by any account the range creates. `Protect-RangePath` now strips
inheritance on `C:\ProgramData\CyberRange` and `C:\CyberRange`, granting SYSTEM +
Administrators only, re-asserted in Phase 4. **Do not relax these ACLs.**

### 1c. Defender never disabled (FIXED — F4)
`Set-MpPreference @{ ... }` was a positional hashtable, not a splat: all seven
toggles threw and were mislabelled as Tamper Protection. Now splatted from a
variable. **Verify on-box** with `Get-MpComputerStatus`.

### 1d. Staged tree loosened to Everyone (FIXED — F25, CRITICAL)
Field operator ran `takeown` + `icacls "C:\CyberRange" /grant Everyone:(OI)(CI)F`
to get a `Set-*` script to run — re-opening F3 with write added, exposing the
staged config (every operator secret) to every account. Real cause: **running
non-elevated** (UAC filters the Administrators token; `EnableLUA=0` needs a
reboot). Fixed: `Protect-RangePath` and the staging step now set owner to
Administrators, strip inheritance, grant only SYSTEM+Administrators, and
explicitly remove Everyone/Authenticated-Users/Users ACEs — so a re-run REPAIRS a
loosened directory. **Correct unstick is to run elevated (+`Unblock-File`), never
`Everyone:F`.** The break-glass pre-flight FAILs if the tree is world-readable. The lock is
applied by the local instance *after* the staging relaunch (never during staging
— locking then relaunching `-File` from the locked path denied the relaunch its
own script); staging `/reset`s a stale `C:\CyberRange` first.
**Update 2026-09-04:** after this kept failing in the field, we stopped
ACL-locking the staged tree entirely — it now inherits normal permissions, which
removed the whole denial class. Only `C:\ProgramData\CyberRange` (the change
manifest / answer key) is still locked. The staged `range.config.psd1` is
consequently readable by local users; acceptable because the operator is
Administrator anyway (F18), and off-boxing the answer key is WP2/WP3 work.

### 1e. Placeholder creds + break-glass failure now hard gates (FIXED — F20/F21)
`Assert-RangeSafety` refuses to build while any shipped placeholder credential is
present (F20); break-glass provisioning failure now blocks the Phase 1 reboot
instead of weakening the box regardless (F21). Both override with `-Force` /
`-AllowPlaceholderCredentials` for off-network dry runs only.

### 2. Unattended promotion runs as SYSTEM
Stage's resume task promotes the DC as SYSTEM. Works in labs but is the
least-certain step; if it fails, re-run `.\Stage-CyberRange.ps1` interactively as
Administrator — it is idempotent and picks up at the promotion step. Option on
the table: run the resume task as the autologon Administrator instead.

Since the 2026-09-07 restructure this runs on a HEALTHY box (firewall up, UAC on,
LSA intact), which removes the most likely reason for it to fail.

### 3. Credential consistency (ACTION REQUIRED)
Since the F1 fix, **`LocalAdminAutoLogonPass` no longer has to match the image —
it overwrites the Administrator password.** That removes the mismatch class of
failure but makes the config value consequential: whatever is in there becomes the
Administrator credential on every clone. It is still the placeholder `Password!`.
Decide the canonical competition credential and set it, along with
`DC.SafeModePassword` and `BreakGlass.Password`. Record all three off-box.

## Next steps

### 1. Re-verify the restructure on hardware (do this first)

No control VALUE changed on 2026-09-07, so this is a regression check. Build a
fresh, snapshotted, standalone Server 2025 VM and work down:

- [ ] `.\Stage-CyberRange.ps1` reaches `STAGED.txt`, surviving the promotion
      reboot and resuming itself. Confirm the DC is up and `analyst` can log in
      **before** running Setup - that is the whole point of the new order.
- [ ] `scripts\directory.ps1` created the OU tree and all eight accounts as
      ORDINARY users: no SPNs, no `DoesNotRequirePreAuth`, no reversible
      encryption, no password in a description.
- [ ] `.\Setup-CyberRange.ps1` reaches `READY.txt` with no failures, and
      `ad-users-weaponise.ps1` stamps the attack attributes onto those SAME
      accounts (it must not create any).
- [ ] `.\Test-RangeConfig.ps1` reports **0 FAIL** (matching 2026-09-06). Any new
      FAIL is a wiring bug from the restructure, not a range-design change.
- [ ] `.\Test-RangeConfig.ps1 -Repair -WhatIf`: expect `OK` for everything, no
      `ERROR` rows.
- [ ] `.\Reset-CyberRange.ps1` (dry run): every category listed, and the firewall
      row **last** in `[network]`.
- [ ] Recovery still works: Win+U at the logon screen gives a SYSTEM prompt, and
      `C:
ange-fix.cmd` exists.

### 2. Then, from `docs/IMPROVEMENT-PLAN.md`

- [ ] **WP1** - the finding register + a scoring baseline. Still the single
      biggest gap: blue-team remediation cannot be graded without it.
- [ ] **WP3** - get the answer key off the participant VM (F18 / F19 remainder).
      Autologon makes the participant a Domain Admin, so the F3 ACL does not keep
      them out of it.
- [ ] **WP5** - telemetry / log collection to the range-administrator box.
- [ ] **WP11** - see the plan.

**WP2 is obsolete.** It specified the golden-image + per-clone-identity model;
that model was removed on 2026-09-07 in favour of building each VM from scratch,
which closes F16 and F17 without any of the clone machinery.


## File map

| Path | What it is |
|---|---|
| `Stage-CyberRange.ps1` | **STEP 1.** Stages the repo to `C:\CyberRange`, runs the pre-flight, provisions the operator account, installs AD DS, promotes the DC, creates the directory. Reboots once and resumes itself |
| `Setup-CyberRange.ps1` | **STEP 2.** Every misconfiguration: the control table, then the AD attack paths, then finalize. `-Only <category>` for targeted re-application |
| `Test-RangeConfig.ps1` | **STEP 3.** Verify every control (PASS/FAIL/WARN/N-A with control IDs). `-Repair` = test -> fix -> re-test, incl. the DC-GPO delegated fixers |
| `Reset-CyberRange.ps1` | Teardown in place (dry run by default). Cannot undo promotion or exposed creds |
| `config/range.config.psd1` | All toggles, credentials, beacon, DC settings |
| `modules/RangeControls.psm1` | **THE CONTROL TABLE.** 125 controls, each declared once: value, control ID, check, revert, rationale |
| `modules/RangeCommon.psm1` | Logging, CSV manifest, safety guard, reg/native helpers |
| `scripts/preflight.ps1` | Safety gates + operator account. Standalone, no module dependency, so it runs on a damaged box |
| `scripts/operator-account.ps1` | Provisions the account you log in as (role-aware: local, or domain on a DC) |
| `scripts/operator-keeper.ps1` | Boot task: re-asserts that account every restart, drops `C:
ange-fix.cmd` |
| `scripts/directory.ps1` | OUs, groups, staff and service accounts - all ordinary |
| `scripts/ad-users-weaponise.ps1` | Stamps Kerberoast / AS-REP / reversible / pw-in-description onto those accounts |
| `scripts/ad-certificates-esc1.ps1` | Enterprise CA + the ESC1 template |
| `scripts/ad-acl-delegation.ps1` | DCSync, GenericAll, unconstrained/constrained delegation |
| `scripts/ad-gpo-legacy.ps1` | GPP `cpassword` in SYSVOL + spray-friendly password policy |
| `scripts/ad-hidden-admins.ps1` | Hidden `*-backup` domain admins |
| `scripts/dc-security-gpo.ps1` | Pushes the downgrades into the Default DC Policy so they survive `gpupdate` (F33) |
| `docs/USER-GUIDE.md` | End-to-end operator guide |
| `docs/BREAK-GLASS.md` | Seven-layer recovery runbook |
| `docs/GRC-CONTROL-MAP.md` | Control mappings (NIST/CIS/STIG/NSA) + scenario gaps |
| `docs/VERIFICATION-SESSION.md` | Primer for a verification-focused session |
| `docs/IMPROVEMENT-PLAN.md` | Topology decisions, findings F16-F24, work packages |
| `docs/archive/` | Superseded docs, kept for provenance only |
| `.attic/` | Pre-restructure copies of the removed scripts. Delete once the rebuild is verified |


## Open questions for the operator

- Is the target already a DC, and did `READY.txt` ever appear? (Tells us how far
  the failed build got.) If the seeded `*-backup` admins do not work, the build
  never reached Phase 3.
- What should the canonical Administrator/competition password be? Needed before
  the F1 fix can be applied.
- What **enforces** the range LAN's isolation from campus — a dedicated VLAN,
  hypervisor-only networking, or a physical air gap? The build disables the
  firewall on all profiles, so that boundary is the only containment left, and it
  now has to hold with peer VMs attacking each other across it.
- **How many participants** (how many clones on the LAN)? Sets the `<nn>` width in
  the per-clone naming scheme (WP2).
- **One administrator box or two?** The C2 role is deliberately exposed to student
  traffic; the answer-key/scoring store should not be. Sharing one VM is workable
  but the risk should be accepted in writing (F23).
- **Which direction does the red cell run?** Is the implant the *live intrusion*
  students defend against, or the *foothold* students use to attack peers? Both are
  planned for, but the answer key wording and the grading split differ (WP7).
- **Does the seeded beacon point at an admin-box sinkhole** (network-detection
  exercise, needs a port distinct from the live C2) or stay at `192.0.2.1`
  (on-disk artifact only)? See WP5.
- **Which CIS Benchmark release** exactly — Server 2022 (mature) or a final 2025
  one? Needed before `Baseline ID` can be filled in `docs/GRC-CONTROL-MAP.md`.
- **Should participants be Administrator on their own box?** Autologon as
  Administrator is what makes F18 unfixable in place. If they are meant to *earn*
  privilege locally, autologon should target an unprivileged account instead.
