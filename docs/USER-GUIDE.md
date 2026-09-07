# User Guide — Windows Server 2025 Cyber Range

How to build a range VM, verify it, get back into it, and fix the things that
actually go wrong.

_Last updated: 2026-09-07, after the hardware build on `WIN-UGR8U7OFA11`.
§9 (Troubleshooting) is the record of what that build hit and how it was fixed._

---

## 1. The short version

On a **fresh, snapshotted, standalone Windows Server 2025 VM**, in an **elevated**
PowerShell:

```powershell
.\Stage-CyberRange.ps1     # 1. Build the domain.      Nothing is weakened.
.\Setup-CyberRange.ps1     # 2. Apply the misconfigs.  This is the range.
.\Test-RangeConfig.ps1     # 3. Verify.  Optional but do it.
```

Each step offers to run the next. `-Auto` on Stage chains all three and reboots
without prompting.

Lost your place? This tells you exactly what to run next, and never changes
anything:

```powershell
.\Test-RangeConfig.ps1 -Next
```

Build one VM per participant. **Do not clone a promoted DC** — every clone would
share `krbtgt` and the domain SID, so a golden ticket forged on one student's VM
would authenticate to all of them.

---

## 2. Why the order is Stage → Setup

Stage builds a small, ordinary, **working** domain. Setup then breaks it.

That order is deliberate. Promotion on an already-weakened box — no firewall, no
UAC, a downgraded LSA — is fragile, and it is where this project's earlier
lockouts came from: the dangerous window was "weakened, mid-reboot, no domain
account yet". Now, if Setup goes wrong, you still have a healthy DC and a working
login to fix it from.

```
Stage                              Setup                          Test
──────────────────────────────     ─────────────────────────      ──────────────
pre-flight gates                   machine controls               125 controls
operator account (+ validated)     AD attack paths                + AD paths live
AD DS + ADCS + SMB1 features       finalize / READY.txt           + recovery layers
        ↓ REBOOT ↓                         ↓ REBOOT ↓             -Repair fixes drift
promote to DC
OU tree, staff + service accounts
STAGED.txt
```

Stage reboots once (to settle the feature installs and complete promotion) and
resumes itself through a SYSTEM task. Setup reboots once at the end, because UAC,
LSA PPL and VBS only take effect on restart.

---

## 3. Before you start

1. **A VM you can snapshot.** Not a box you cannot roll back. Take the snapshot
   *before* step 1.
2. **Windows Server 2025**, freshly installed, **standalone — never domain-joined.**
   Stage refuses on a domain member: it promotes a standalone server into its
   *own* new forest, which a member can never do.
3. **Isolated networking.** The build disables the firewall on every profile,
   enables SMB1 and drops NLA.
4. **An elevated PowerShell.** The single most common cause of confusing failures.
5. If the repo came from a share or USB:
   `Get-ChildItem -Recurse <repo> | Unblock-File`

---

## 4. Configure

Edit `config\range.config.psd1`. Only a handful of values matter:

| Setting | What it is |
|---|---|
| `Confirmed = $true` | The isolation acknowledgement. Nothing runs without it. |
| `Analyst.Password` | **Your login.** Record it off-box. |
| `DC.SafeModePassword` | DSRM / directory-restore. Record it off-box. |
| `LocalAdminAutoLogonPass` | **Becomes the Administrator password**, and is deliberately exposed in cleartext in the registry — that is the lesson, not a bug. |
| `HiddenAdminPassword` | Red-team loot. Keep it crackable; that is the point. |
| `DC.DomainName` / `DC.NetbiosName` | The forest to create. |
| `BeaconHost` | Leave at `192.0.2.1` (RFC 5737 — routes nowhere real). |

The build **refuses to run** while `Analyst.Password`, `DC.SafeModePassword` or
`LocalAdminAutoLogonPass` is still the shipped example value. That gate is real —
it once checked for values the repo did not ship and therefore protected nothing.

Everything else (`Categories.*`, `DC.*` toggles, `RemoveDefenderFeature`,
`DisableEventLogService`, `AccessibilityShell`, `OperatorKeeper`) has a sane
default. Leave it alone unless you know why you are changing it.

---

## 5. Step 1 — Stage

```powershell
.\Stage-CyberRange.ps1
```

What it does, in order:

1. Copies the repo to `C:\CyberRange` and re-runs from there. Required: the
   SYSTEM task that carries the build across the promotion reboot runs before any
   user logs on, and cannot see a mapped drive or USB stick.
2. **Pre-flight gates.** Stops if the config is unsafe, the host is domain-joined,
   the beacon target is routable, or the answer key is readable by non-admins.
3. **Provisions your operator account and proves it authenticates** — before
   anything else happens. This is your way back in.
4. Installs AD DS + DNS, and pre-installs **AD CS** and **FS-SMB1** so the reboot
   below completes them (see §9.2 — this was a real failure).
5. **Reboots**, resumes itself, and promotes into a new forest.
6. Creates the OU tree, staff and service accounts, and groups — all ordinary.

**Do not log in between reboots.** The domain accounts do not exist until it
finishes. Watch instead:

```powershell
Get-Content C:\ProgramData\CyberRange\logs\rangebuild-*.log -Tail 40 -Wait
```

Done when `C:\ProgramData\CyberRange\STAGED.txt` appears. **Confirm you can log in
as `analyst` before running Setup** — that is the entire point of building the
structure first.

Re-running Stage is safe. Every step is idempotent and skips work already done.

## 6. Step 2 — Setup

```powershell
.\Setup-CyberRange.ps1
```

Applies the machine controls from the control table, then the AD attack paths
(Kerberoast, AS-REP, ESC1, DCSync, delegation, GPP cpassword, hidden domain
admins), then finalizes and reboots.

`scripts\ad-users-weaponise.ps1` stamps the attack attributes onto the **same**
accounts Stage created — it never creates a user. If it reports an account
missing, Stage did not finish.

Done when `READY.txt` appears. **Read it** — it states whether the run was clean
or finished with failures.

Targeted re-application on a built box:

```powershell
.\Setup-CyberRange.ps1 -Only smb-network
```

## 7. Step 3 — Test

```powershell
.\Test-RangeConfig.ps1 -ShowControl
```

Reports PASS / FAIL / WARN / N-A per control with NIST/CIS mappings, so the output
doubles as the blue team's scoring baseline. `[live]` checks read the running
subsystem — can lsass actually be opened, is the RDP listener really NLA-free,
what does the KDC actually allow.

```powershell
.\Test-RangeConfig.ps1 -Next               # what should I run next?
.\Test-RangeConfig.ps1 -Repair -WhatIf     # what has drifted?
.\Test-RangeConfig.ps1 -Repair             # fix drift, then re-test each control
.\Test-RangeConfig.ps1 -Format Csv -Out C:\Temp\range.csv
```

`-Repair` needs elevation. A fix that does not change the test result is reported
**STILL-FAILING**, never "fixed" — that distinction is the whole point of the
re-test.

---

## 8. Getting back in

Three things exist purely to keep *you* able to log in. None belong in a
participant brief.

- **`analyst`** — your login, provisioned before the domain is even built.
- **The operator keeper** — a permanent SYSTEM boot task that re-asserts `analyst`
  on every restart and drops `C:\range-fix.cmd`.
- **The accessibility shell** — Win+U or Shift ×5 at the logon screen gives a
  SYSTEM prompt with **no password at all**.

Work down in order. Full detail in [BREAK-GLASS.md](BREAK-GLASS.md):

1. **Revert the snapshot.** Fastest and cleanest.
2. **`analyst`** — the keeper re-asserts it every boot.
3. **Win+U / Shift ×5**, then type `C:\range-fix.cmd`.
4. The seeded `*-backup` admins → DSRM → an offline Windows RE registry edit.

| Symptom | Meaning |
|---|---|
| Every domain account fails on a DC | Kerberos etypes pinned to RC4-only — see BREAK-GLASS |
| `analyst` works, `Administrator` does not | Administrator's password is `LocalAdminAutoLogonPass` |
| `*-backup` accounts missing | Setup never completed |
| Nothing works, no accessibility shell | `AccessibilityShell = $false`, or Setup died early |

---

## 9. Troubleshooting

### 9.1 — First, ask the tool

```powershell
.\Test-RangeConfig.ps1 -Next
```

It reads the `STAGED.txt` / `READY.txt` markers and this run's own results, and
prints the one command to run next: build, apply, repair drift, bring ADWS up, or
tear down. It is read-only. Start here before reading the rest of this section.

---

### 9.2 — Found on the hardware build (2026-09-07)

These are real, were diagnosed on `WIN-UGR8U7OFA11`, and are **fixed in the
current tree**. They are documented because the symptoms are misleading and
because an older VM may still show them.

#### A disabled ADWS silently sinks every AD step (F39)

**Symptom.** Eight unrelated-looking FAILs at once: `analyst` missing, all five
hidden domain admins missing, autologon withheld, AD-dependent checks failing.
The log says "AD DS unreachable" after a long wait.

**Cause.** All three AD-wait loops called
`Start-Service NTDS,ADWS,DNS,Netlogon -ErrorAction SilentlyContinue`.
**`Start-Service` cannot start a service whose StartType is `Disabled`** — it
throws, `SilentlyContinue` swallows the error, and the loop just times out. On the
field DC, ADWS was `Disabled`. Every directory step then failed for that one
hidden reason.

**Fixed by** re-enabling any of NTDS / DNS / ADWS / Netlogon found `Disabled`
before starting it, in Stage, Setup **and** the operator keeper — so the keeper
now self-heals a disabled ADWS on every boot.

**On a box that still shows it:**
```powershell
Set-Service ADWS -StartupType Automatic; Start-Service ADWS
.\Test-RangeConfig.ps1 -Next
```

> Nothing in the current tree disables ADWS, so the original disable came from
> outside it (an older build, or by hand). The self-heal makes the source moot.

#### AD CS and SMB1 need a reboot the build never gave (F41)

**Symptom.** On a **clean** rebuild: `[dc-adcs] CertSvc running`,
`[dc-adcs] ESC1 published` and `[live] SMB1 enabled` all FAIL. Setup logs
"ADCSDeployment module not found". Confusingly, earlier builds passed.

**Cause.** Installing the **AD CS role leaves it
`InstallState=InstallPending` / `RestartNeeded=Yes`.** The `ADCSDeployment` module
and `Install-AdcsCertificationAuthority` **do not exist**, and `CertSvc` never
starts, until the box reboots. Setup was configuring the CA in the same session,
so it always failed on a clean build — the earlier "passes" were on a contaminated
box where the feature was already fully installed from a previous run. FS-SMB1 is
the same: the SMB1 server protocol is not live until a reboot completes the
install.

**Fixed by** pre-installing `ADCS-Cert-Authority`, `ADCS-Web-Enrollment` and
`FS-SMB1` in **Stage**, where the existing promotion reboot completes the pending
install. By the time Setup runs, the features are settled and the CA configures
in-session. Gated on `DC.InstallAdcs` and `Categories.SmbNetwork`.

**On an already-built box:**
```powershell
Restart-Computer -Force
# then, after it comes back:
.\scripts\ad-certificates-esc1.ps1
Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
```

**Verified on hardware:** after the reboot and re-run, `CertSvc` came up, ESC1
published, and SMB1 went live — all three FAILs cleared.

#### "SMB server signing not offered" will never pass on a DC (F40)

**Symptom.** `smb.srv.enable` (`EnableSecuritySignature=0`) stays FAIL on the DC
no matter what you do — while the adjacent `RequireSecuritySignature=0` passes
fine.

**Cause.** A **domain controller always OFFERS SMB signing**, because SYSVOL and
NETLOGON require it. The server service re-forces `EnableSecuritySignature=1`
regardless of the registry *or* the Default Domain Controllers Policy.

**This was never blocking relay.** Only *required* signing blocks NTLM relay, and
that is off (`RequireSecuritySignature=0`, PASS). The control was measuring
something that does not matter and cannot be changed.

**Fixed by** making the control role-aware: **N-A on a DC** with that explanation,
still PASS/FAIL on a non-DC. Same category as the F38 log-size N-A.

**On a running DC:** update `modules\RangeControls.psm1` on the box and re-run
`Test-RangeConfig.ps1`. No rebuild needed.

---

### 9.3 — Gates that stop the build on purpose

These are guard rails, not bugs. Each stops the build **before** anything is
weakened.

| What you see | Why | Fix |
|---|---|---|
| `PLACEHOLDER CREDENTIALS PRESENT: ...` | `Analyst.Password`, `DC.SafeModePassword` or `LocalAdminAutoLogonPass` is still the shipped example value, and these become real credentials on the VM | Set them in `config\range.config.psd1`, record off-box. `-Force` overrides for an off-network dry run only |
| `This host is a MEMBER of domain '...'` | A DC build creates a *new forest*; a domain member cannot | `Add-Computer -WorkgroupName WORKGROUP -Force -Restart`, or start from a clean never-joined snapshot |
| `SAFETY GUARD TRIPPED` | `Confirmed` is not `$true` | Set it, once you have confirmed the VM is isolated |
| `PRE-FLIGHT FAILED` | A blocking gate failed; nothing has been handed off and nothing weakened | Read the BLOCKED/FAIL gate names above it and fix that specific thing |
| `Setup must run from C:\CyberRange` | You ran Setup from the repo instead of the staged copy | Run `.\Stage-CyberRange.ps1` first |
| `DC.Enabled = $true but this host is NOT a domain controller` | Setup was run before Stage finished | Run Stage first, or set `DC.Enabled = $false` to weaken a standalone box deliberately |
| `-Repair writes to HKLM ... run this in an ELEVATED PowerShell` | Exactly that | Re-open PowerShell as Administrator |
| `A REBOOT IS PENDING -- that alone fails the promotion prereq` | Windows has servicing work queued | Reboot once by hand; the resume task retries promotion automatically |

**"Access denied" is almost always elevation.** It is **never** fixed by
`takeown` / `icacls Everyone:F` on the staged tree — that re-opens the answer-key
exposure the build exists to prevent, and does not fix the cause.

---

### 9.4 — Rows that look like failures but are not

Do not chase these. They are documented, accepted deviations.

| Row | State | Why |
|---|---|---|
| Event-log channel max size | N-A | **F38.** Resisted every supported mechanism on 2025 — the legacy key is not authoritative, `wevtutil sl` is denied on Security, the policy key is KB-denominated. It gates no attack path |
| SMB server signing not offered (on a DC) | N-A | **F40.** See §9.2 — a DC cannot stop offering signing, and it is not the relay-relevant toggle |
| HiveNightmare hive DACLs | N-A | The kernel holds SAM/SYSTEM/SECURITY open; `icacls` is denied even after `takeown`. The **VSS shadow copy** is the exploitable artifact, and it is checked separately |
| PowerShell v2 engine | N-A | Payload removed on 2025; enabling it needs Windows Update, which the build disables (F13) |
| `LmCompatibilityLevel=0` | WARN | NTLMv1 is removed in 2025 — a genuine config finding, not a live exploit (F9) |
| `DisableAntiSpyware` | WARN | Ignored since the Aug-2020 platform update. Kept for parity with the 2019 lesson plan |
| Unconstrained delegation | WARN | Set on a *user*; coercion needs a computer account (F14) |
| Sysmon neutralized | N-A | Only meaningful if the blue team deployed Sysmon |
| Fake service `WinTelemetryHelper` **Stopped** | PASS | Expected. It is `powershell.exe` running a script, not a service binary, so it never answers the SCM (error 1053). The artifact is its *existence* and Automatic start type |

---

### 9.5 — Drift during an exercise

The blue team fixing things is the *point*. To see what they have changed:

```powershell
.\Test-RangeConfig.ps1                     # what is still as-built?
.\Test-RangeConfig.ps1 -Repair -WhatIf     # what would I put back?
```

If a control comes back **STILL-FAILING** after `-Repair` on a DC, it is almost
certainly **GPO-owned**. SMB signing, `NoLmHash` and the log sizes are re-asserted
by the Default Domain Controllers Policy on every refresh, so a local registry
write "succeeds" and then silently reverts. `-Repair` handles this by re-running
`scripts\dc-security-gpo.ps1` and forcing `gpupdate`, then re-testing. `-SkipGpo`
turns that off, and the honest result is then STILL-FAILING.

---

## 10. Teardown

```powershell
.\Reset-CyberRange.ps1            # dry run — shows everything it would undo
.\Reset-CyberRange.ps1 -Execute   # then type TEARDOWN
```

Re-hardens the machine and removes the range's accounts, persistence, shares and
AD attack paths. It **cannot** undo DC promotion, exposed credentials, or missed
patches. If the box is going back to anything that matters, rebuild it — or roll
back to the snapshot you took in §3.

---

## 11. Do not

- **Hand out the manifest.** `C:\ProgramData\CyberRange\logs\` holds every seeded
  password in cleartext. It is the answer key. Collect it off-box.
- **Loosen ACLs to get unstuck.** Run elevated instead.
- **Clone a promoted DC** to make more participant VMs. Build each from scratch.
- **Put `analyst` in a participant brief.**
- **Run any of this on a box with a route to a real network.**
