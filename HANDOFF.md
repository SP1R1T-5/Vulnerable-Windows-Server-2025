# Handoff / Progress Tracker

Living status doc for the Windows Server 2025 cyber-range builder. Keep it current:
when you finish a work session, update **Current status**, **Known issues**, and
**Next steps**, and add a line to [CHANGELOG.md](CHANGELOG.md).

_Last updated: 2026-09-06 (Phase 1 verified on hardware; WP2/F16 implemented)_

> **2026-09-06:** Phase 1 is complete and verified on hardware (0 FAIL), and
> **WP2 / F16 is implemented** — the golden image is now cut *before* promotion
> and each clone promotes its own forest. See **Current status** below.

---

## Purpose

Provision an intentionally vulnerable Windows Server 2025 **Domain Controller**
image for a university red-vs-blue lab (config management, vuln management, IR,
and collegiate-competition tradecraft). Built once into a golden image, then
cloned to **one VM per participant**. Educational use only.

**Topology (decided 2026-09-03, design session):** one VM per participant, all on
a **shared range LAN** with no route to campus or the internet. Participants'
lateral-movement targets are **each other's VMs** — so relay, NTLM downgrade,
WinRM/RDP movement and delegation coercion are live, not inert. A
**range-administrator box sits on the same subnet**: it is the answer-key store,
log collector, offline package source, scoring host, and the **red-cell C2 that
delivers implants for initial access**. **Range administrators perform first boot
and personalization** before a student receives the VM.

That makes the range **multi-tenant with live offensive infrastructure**, which the
current build was not designed for; see findings **F16–F24** in
[docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md).

**Scoring baseline (same session):** CIS Microsoft Windows Server Benchmark,
pinned release. NIST SP 800-63B is a documented deviation, taught as the framework
conflict, not used for grading.

## Current status

> ### PHASE 1 COMPLETE — verified on hardware 2026-09-06
> `WIN-UGR8U7OFA11`, Server 2025, promoted DC for `range.lab`.
> **`Test-RangeConfig.ps1`: 0 FAIL.** Every attack path confirmed live: ESC1
> published and enrollable, Kerberoast with RC4-stamped SPNs, AS-REP roasting,
> DCSync, GenericAll on Domain Admins, constrained + unconstrained delegation,
> MAQ=10, GPP cpassword in SYSVOL, SMB1 with signing off, LSASS confirmed
> dumpable via OpenProcess, the full persistence set, and working break-glass.
> Remaining rows are documented N-A (see F38, and HiveNightmare / PSv2 / Sysmon)
> or honest WARNs (NTLMv1 removed on 2025, F14 delegation-on-a-user, KDC etype note).
>
> This is the **build** milestone. The topology work (F16–F24 in
> [docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md)) is untouched — most
> importantly **F16**: cloning after promotion means every participant VM shares
> `krbtgt` and the domain SID. Do not cut and distribute a golden image until
> that is resolved.

- **Framework:** complete and parse-clean — 28 `.ps1`/`.psm1` files parse, the
  `.psd1` loads.
- **One-shot builder:** `Setup-CyberRange.ps1` — **validated end-to-end on a real
  Server 2025 VM** (2026-09-06), including both reboots and unattended resume.
- **Teardown:** `Reset-CyberRange.ps1` undoes the range in place (dry run by
  default) for when a snapshot revert is not wanted. It cannot undo promotion,
  exposed credentials, or missed patches — rebuild if the box matters.
- **DC scenarios:** `scripts/dc/00`–`60`, all verified live. ESC1 was broken as
  written (F8/F34: duplicate template OID, then a V1/V2 schema hybrid the CA
  rejected) and is now published and enrollable.
- **Verification status:** Part B executed on hardware 2026-09-06 —
  `Test-RangeConfig.ps1` reports **0 FAIL**. The 2026-09-03 static review
  ([docs/VERIFICATION-REPORT-2026-09-03.md](docs/VERIFICATION-REPORT-2026-09-03.md))
  is now history: F1–F15 are closed or documented deviations, and F26–F38 were
  found and closed during the hardware bring-up (see CHANGELOG).
- **Break-glass:** wired into the build. `Setup-CyberRange.ps1` provisions the
  recovery account in Phase 1 before any weakening, and again as a domain account
  in Phase 3 after promotion. `scripts/00-break-glass.ps1` also runs standalone as
  a pre-flight and as a recovery tool (see [docs/BREAK-GLASS.md](docs/BREAK-GLASS.md)).
- **GRC:** misconfigurations are now mapped to published controls in
  [docs/GRC-CONTROL-MAP.md](docs/GRC-CONTROL-MAP.md). The single biggest gap is
  that there is no measurable baseline, so blue-team remediation cannot be scored.
- **Design:** [docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md) — 12 work
  packages, findings F16–F24. **WP2 is now implemented**, closing **F16** in
  source: `-Mode Image` cuts the golden image *before* promotion, and
  `Initialize-RangeClone.ps1` gives each clone its own name, domain and secrets so
  it promotes its own forest — unique domain SID and `krbtgt` per participant.
  **Unproven on hardware:** the acceptance test is cross-VM (forge a golden ticket
  on clone A, confirm clone B rejects it). Do not distribute an image until that
  test passes. WP1, WP3, WP5, WP11 remain unimplemented.

## Pre-build drill (do this every time)

```powershell
# 1. Snapshot the VM on the hypervisor.
.\scripts\00-break-glass.ps1          # 2. read-only pre-flight; exits 1 if blocked
.\scripts\00-break-glass.ps1 -Apply   # 3. create + validate the recovery account
.\scripts\00-break-glass.ps1          # 4. re-run until PASS
.\Stage-CyberRange.ps1                # 5. only now (Stage 1 -> engine)
```

## How to run (current)

Two-stage. Elevated PowerShell, once: `.\Stage-CyberRange.ps1`. Stage 1 copies the
repo to `C:\CyberRange` and hands off to the engine `Setup-CyberRange.ps1` from
that local copy (running the engine directly from the share now refuses). It
applies everything, reboots ~2× (auto-resume), and writes
`C:\ProgramData\CyberRange\READY.txt` when finished. Full change list is the
manifest CSV in `C:\ProgramData\CyberRange\logs\`. **Always snapshot the VM
before running**, and don't snapshot the golden image until `READY.txt` exists.

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
[docs/VERIFICATION-REPORT-2026-09-03.md](docs/VERIFICATION-REPORT-2026-09-03.md)
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
The resume task promotes the DC as SYSTEM. Works in labs but is the least-certain
step; if it fails, run `scripts/dc/00-promote-dc.ps1` interactively as
Administrator and the orchestrator resumes at Phase 3 on next boot. Option on the
table: run the resume task as the autologon Administrator instead.

### 3. Credential consistency (ACTION REQUIRED)
Since the F1 fix, **`LocalAdminAutoLogonPass` no longer has to match the image —
it overwrites the Administrator password.** That removes the mismatch class of
failure but makes the config value consequential: whatever is in there becomes the
Administrator credential on every clone. It is still the placeholder `Password!`.
Decide the canonical competition credential and set it, along with
`DC.SafeModePassword` and `BreakGlass.Password`. Record all three off-box.

## Next steps

### Where to pick up

**WP2 is implemented but unproven on hardware.** The only outstanding acceptance
test is cross-VM and needs two clones from one image:
- [ ] Cut an image with `-Mode Image`, sysprep, clone twice.
- [ ] `Initialize-RangeClone.ps1 -CloneId 01` and `-CloneId 02`, let both promote.
- [ ] **Forge a golden ticket on clone 01 and confirm clone 02 rejects it.** That
      single test is what proves F16 is closed.
- [ ] `Get-ADUser krbtgt -Properties objectSid` differs between the two.
- [ ] `nltest /dsgetdc:r01.range.lab` resolves unambiguously with both online.
- [ ] `Get-RangeCloneSecret.ps1 -CloneId 01` reproduces clone 01's real passwords.

**Then, in rough priority order from `docs/IMPROVEMENT-PLAN.md`:**
- [ ] **WP3** — get the answer key off the participant VM (F18/F19 remainder).
      Small, and it is the last credential-exposure item.
- [ ] **WP1** — control-mapped finding register + scorable compliance output (G4).
      Everything else in the plan hangs off it.
- [ ] **WP11** — multi-tenant rules of engagement and the operations runbook
      (F23/F24). Needed before students share a LAN.
- [ ] **WP5** — advanced audit policy (G2). Largest content gain per unit effort.

**Deferred deliberately:** F38 (event-log channel size) is an accepted deviation,
documented in `Test-RangeConfig.ps1` and the changelog. Do not reopen it without
new evidence — five mechanisms were tried and recorded.

**Done — F1–F7 applied 2026-09-03:**
- [x] Autologon triad fixed: password set + validated, `DefaultDomainName` written,
      `ForceAutoLogon` never set and stripped if present (F1).
- [x] Break-glass runs first in Phase 1 and again post-promotion in Phase 3 (F2).
- [x] `C:\ProgramData\CyberRange` and `C:\CyberRange` ACL-locked (F3).
- [x] `BeaconHost` → `192.0.2.1` (F6).
- [x] `Set-MpPreference` splat fixed (F4).
- [x] Failed phases no longer advance; `-Force` to override (F7).
- [x] `Invoke-RangeBuild.ps1` written — `-Only`, `-SkipDC`, `-List` (F5).
      *(REMOVED 2026-09-06: superseded by `Repair-RangeConfig.ps1` /
      `Reset-CyberRange.ps1`, and it bypassed the engine's safety gates.)*

**Done — 2026-09-06 (Phase 1 verified on hardware, then WP2):**
- [x] Phase 1 clean end-to-end on `WIN-UGR8U7OFA11`: **0 FAIL**.
- [x] F26/F27/F28/F29/F30/F31/F32/F33/F34/F35/F36/F37 closed — see CHANGELOG.
- [x] F38 accepted as a documented deviation rather than chased further.
- [x] `Repair-RangeConfig.ps1` and `Reset-CyberRange.ps1` added.
- [x] **WP2 / F16:** `-Mode Image`, `Initialize-RangeClone.ps1`,
      `Get-RangeCloneSecret.ps1`, and `Get-RangeCloneIdentity` in `RangeCommon`.
      Five per-clone secrets (the spec's four **plus `Analyst.Password`**, which
      the spec missed — `analyst` is a Domain Admin on every clone, so a shared
      password is the same cross-VM compromise through a different door).

**Done — 2026-09-04 (F25 + WP3 gates F19–F21):**
- [x] F25: staged-tree ACL is self-repairing; no `Everyone:F` needed (run elevated).
- [x] F20: placeholder credentials block the build (`Assert-RangeSafety`).
- [x] F21: break-glass provisioning failure blocks the Phase 1 reboot.
- [x] F19 (partial): `READY.txt` no longer points at the answer key. Full
      manifest/answer-key file split still open under WP3.

**Blockers — before any build:**
- [ ] **Set the real credentials — now ENFORCED (F20).** The build refuses to run
      while `LocalAdminAutoLogonPass` (`Password!`), `DC.SafeModePassword`,
      `BreakGlass.Password` or `HiddenAdminPassword` is a shipped placeholder.
      `LocalAdminAutoLogonPass` *becomes* the Administrator password. Record all off-box.
- [ ] Snapshot, then `.\scripts\00-break-glass.ps1` must print PASS.

**Blockers — before any golden image is CUT AND DISTRIBUTED:**
- [ ] **F16 — move the image cut point before DC promotion** (WP2). Cloning a
      promoted DC gives every participant the same `krbtgt` and domain SID; on the
      shared LAN one forged golden ticket owns the whole range. Re-cutting the
      image is the only fix once clones exist.
- [ ] **F17 — per-clone computer/domain/NetBIOS name.** Nothing renames the
      computer today, and every clone claims `range.lab` / `RANGE` on one segment.
- [ ] **F18 / F19-remainder — get the answer key off the participant VM.** Autologon
      makes the participant a Domain Admin, so the F3 ACL does not keep them out of
      it. (`READY.txt` no longer points at it — F19 done; the manifest/answer-key
      file split and off-box pull are still open.)

**Then verify on a snapshotted VM:**
- [ ] Full `Setup-CyberRange.ps1` run to `READY.txt`, then the Part B matrix.
- [ ] Treat these as **expected failures until proven otherwise**: ESC1 (needs
      `StrongCertificateBindingEnforcement=1` and a unique template OID, F8),
      NTLMv1 (removed in 24H2/2025, F9), RC4 Kerberos (KDC etypes never set, F10),
      LDAP signing/channel binding (never downgraded, F11).
- [ ] Confirm ESC1 with `certipy find -vulnerable`; DCSync/GenericAll in
      BloodHound; GPP cpassword readable in SYSVOL.
- [ ] Fix `dc/10` idempotency — SPNs are only applied on the create branch, so a
      Phase-3 retry silently produces zero Kerberoast targets (F12). This matters
      more now: Phase 3 re-runs `20-credential-exposure.ps1` on a DC, so retries
      are a normal path.
- [ ] Verify the two new Phase-3 steps on a real DC: the domain break-glass
      account, and the autologon re-assert with `DefaultDomainName=RANGE`.

**GRC / content — now planned as work packages in
[docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md):**
- [x] **G1 topology decided** — one VM per participant on a shared range LAN;
      peers are the lateral-movement targets. Phase 0 of the design prompts is
      answered (decisions D1–D5 in the plan).
- [x] **Baseline authority decided** — CIS Benchmark governs scoring; NIST
      SP 800-63B is a documented deviation. **Still to do:** pin the exact
      benchmark release and fill the `Baseline ID` column in the control map.
- [ ] **WP1 (do first):** finding register + `Test-RangeCompliance.ps1` — closes
      G4 and makes every other gap gradable.
- [ ] **WP2:** clone identity + first-boot personalization — closes F16/F17.
- [ ] **WP3:** pre-build and hand-off safety gates — closes F18–F21. Small.
- [ ] **WP4:** make the shipped techniques actually work — F8–F13, F15.
- [ ] **WP5–WP12:** audit policy, account lifecycle, IR narrative, sensitive data,
      vuln-management content, GRC templates, rules of engagement, reset tooling.

## File map

| Path | Role |
|---|---|
| `Stage-CyberRange.ps1` | Stage 1: stage repo to C:\CyberRange, then call the engine. `-Mode Image` for a class build |
| `Setup-CyberRange.ps1` | Stage 2 engine: phases, reboot-resume (runs from C:\CyberRange) |
| `Resume-CyberRange.ps1` | Manual resume when auto-resume stalls; `-StatusOnly` reports without acting |
| `Initialize-RangeClone.ps1` | **Per-clone first boot (class builds).** Derives identity + secrets, starts that clone's own promotion (WP2/F16) |
| `Get-RangeCloneSecret.ps1` | Instructor-side credential recovery from the master secret. Admin box only |
| `Test-RangeConfig.ps1` | Read-only post-build checker (PASS/FAIL/WARN/N-A per control, with control IDs) |
| `Repair-RangeConfig.ps1` | Write-enabled companion: test -> fix -> re-test, incl. the DC-GPO class |
| `Reset-CyberRange.ps1` | Teardown in place (dry run by default). Cannot undo promotion or exposed creds |
| `config/range.config.psd1` | All toggles, passwords, beacon, DC settings |
| `modules/RangeCommon.psm1` | Logging, manifest, safety guard, reg/native helpers |
| `scripts/00-break-glass.ps1` | **Pre-flight + recovery. Run before every build.** Standalone, no module dependency |
| `scripts/10`–`90`, `75` | Standalone misconfig categories |
| `scripts/dc/00`–`50` | DC promote + attack-path seeding |
| `docs/VERIFICATION-SESSION.md` | Primer for a verification-focused session |
| `docs/VERIFICATION-REPORT-2026-09-03.md` | Latest verification pass — 15 findings, 3 blockers |
| `docs/BREAK-GLASS.md` | Six-layer recovery runbook + pre-build drill |
| `docs/GRC-CONTROL-MAP.md` | Control mappings (NIST/CIS/STIG/NSA) + 11 scenario gaps |
| `docs/IMAGE-DESIGN-PROMPTS.md` | Layer-by-layer prompt library for the image design doc |
| `docs/IMPROVEMENT-PLAN.md` | **Topology decisions D1–D5, findings F16–F22, and the 12 work packages. Start here for build work.** |

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
