# Setup Guide — Windows Server 2025 Cyber Range

End-to-end: what the system is, how to build it, how to clone it safely for a
class, how to verify it, and how to get back in when something goes wrong.

_Last updated: 2026-09-06. Phase 1 verified on hardware; WP2 (clone identity)
implemented but not yet run on hardware._

---

## 1. Pick your build mode first

There are two, and choosing wrong is expensive.

| | **Single VM** | **Class of VMs** |
|---|---|---|
| Command | `.\Stage-CyberRange.ps1` | `.\Stage-CyberRange.ps1 -Mode Image` |
| Result | One finished DC | An unpromoted golden image to clone |
| Use for | Development, testing, a one-person lab | Anything with more than one participant |

**If more than one person will get a VM, you must use `-Mode Image`.** An image
cut *after* promotion gives every clone the same domain SID and the same `krbtgt`,
so a golden ticket forged on one student's VM is valid on every other student's
VM. That is finding **F16**, and it cannot be fixed by renaming clones afterwards
— the image has to be re-cut.

---

## 2. What this thing is

An **intentionally vulnerable** Windows Server 2025 image for a red-vs-blue lab,
built by a two-stage system that has to survive two reboots:

```
Stage-CyberRange.ps1        Stage 1. Copies the repo to C:\CyberRange and
        |                   launches the engine from that local copy.
        v
Setup-CyberRange.ps1        Stage 2, the ENGINE. Refuses to run from anywhere
        |                   else -- a SYSTEM task at boot cannot see your mapped
        |                   drive or USB stick.
        v
   PHASE 1  machine-level weakening + AD DS role
            -Mode Image STOPS HERE (unpromoted) ---> sysprep, snapshot, clone
   PHASE 2  promote to domain controller --------> REBOOT
   PHASE 3  seed the AD attack paths
   PHASE 4  finalize, drop READY.txt
```

Progress lives in `C:\ProgramData\CyberRange\setup-state.json`. After each reboot
a SYSTEM scheduled task resumes the build with no login required — deliberately,
because promotion destroys the local SAM and the domain accounts you would log in
with do not exist until Phase 3.

### The scripts

| Script | What it is for |
|---|---|
| `Stage-CyberRange.ps1` | **Start here.** Stages and launches the build |
| `Setup-CyberRange.ps1` | The engine. Runs only from `C:\CyberRange` |
| `Resume-CyberRange.ps1` | Continue after a reboot when auto-resume did not |
| `Initialize-RangeClone.ps1` | Per-clone first boot (class builds only) |
| `Get-RangeCloneSecret.ps1` | Instructor: recover any clone's credentials |
| `Test-RangeConfig.ps1` | Read-only verification, 130+ checks |
| `Repair-RangeConfig.ps1` | Fix controls that drifted or never applied |
| `Reset-CyberRange.ps1` | Tear the range down in place |

### Three things exist purely to keep *you* able to log in

`analyst` (your normal login, never rewritten by the build), `rangebreak`
(break-glass, provisioned before the first weakening step), and the **operator
keeper** — a permanent SYSTEM-at-boot task that re-asserts `analyst` on every
boot and drops `C:\range-fix.cmd`. There is also an accessibility shell: Win+U at
the logon screen gives a SYSTEM prompt with no password.

None of these belong in a participant brief.

---

## 3. Prerequisites

1. **A VM you can snapshot.** Not a box you cannot roll back.
2. **Windows Server 2025**, freshly installed, **standalone — never domain-joined.**
   The build refuses to run on a domain member (F29): a DC build promotes a
   standalone server into its *own* new forest, which a member can never do.
3. **Isolated networking.** The build disables the firewall on every profile,
   enables SMB1 and drops NLA.
4. **An elevated PowerShell.** Not optional, and the single most common cause of
   confusing failures.
5. If the repo came from a share or USB: `Get-ChildItem -Recurse <repo> | Unblock-File`

> If a script says "access denied", the answer is to run elevated. It is **never**
> to `takeown` / `icacls Everyone:F` the staged tree — that re-opens the
> answer-key exposure the build exists to prevent, and does not fix the cause.

---

## 4. Build a single VM

### Step 0 — Snapshot
Take a checkpoint. Everything below assumes you can return to it.

### Step 1 — Configure
Edit `config\range.config.psd1`:
- `Confirmed = $true`
- `LocalAdminAutoLogonPass` — **this becomes the Administrator password**
- `Analyst.Password`, `BreakGlass.Password`, `DC.SafeModePassword` — real values
- `DC.DomainName` / `DC.NetbiosName`, and `BeaconHost` (leave at `192.0.2.1`)

The build refuses to run with the shipped placeholder credentials unless you pass
`-Force`.

### Step 2 — Pre-flight and break-glass
```powershell
.\scripts\00-break-glass.ps1          # read-only; exits non-zero and says why
.\scripts\00-break-glass.ps1 -Apply   # creates AND authenticates the recovery account
.\scripts\00-break-glass.ps1          # re-run until PASS
```

### Step 3 — Build
```powershell
.\Stage-CyberRange.ps1
```
That is the whole command. **Do not run `Setup-CyberRange.ps1` directly** — it
refuses to run outside the staged path, by design.

### Step 4 — Wait through two reboots

| Phase | What happens |
|---|---|
| 1 | Break-glass + analyst created, all machine weakening, AD DS role staged. **Reboot 1** |
| 2 | Promotion to DC. **Reboot 2** (triggered by promotion) |
| 3 | Operator accounts re-created as *domain* accounts, AD attack paths seeded |
| 4 | Resume task removed, answer key ACL'd, `READY.txt` written |

**Do not log in between phases** — after reboot 2 the domain accounts may not
exist yet. Watch instead:
```powershell
Get-Content C:\ProgramData\CyberRange\logs\rangebuild-*.log -Tail 40 -Wait
```

If auto-resume stalls: `C:\CyberRange\Resume-CyberRange.ps1` (add `-StatusOnly`
to look before you leap).

### Step 5 — Done
`READY.txt` appears. Log in as **`analyst`**.

---

## 5. Build a class (golden image + clones)

This is the F16-safe path. Each clone promotes **its own forest**, so unique
domain SIDs and unique `krbtgt` come for free.

### Step 1 — Cut the image (once)
Steps 0-2 above, then:
```powershell
.\Stage-CyberRange.ps1 -Mode Image
```
Phase 1 runs and **stops, unpromoted**. `IMAGE-READY.txt` appears with the
procedure. The resume task is deliberately not registered, so this image will not
promote itself if it reboots.

### Step 2 — Generalize and clone
```powershell
C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown
```
Then snapshot/export and clone per participant.

> If sysprep fails on the weakened image, **clone anyway.** Sysprep only fixes the
> machine SID and install id. The isolation that matters for F16 comes from
> per-clone promotion, so F16 stays closed either way.

### Step 3 — Personalize each clone (range admin, at first boot)
```powershell
C:\CyberRange\Initialize-RangeClone.ps1 -CloneId 07
```
Prompts for the **range master secret**, then names the VM `RANGE07-DC01`, gives
it domain `r07.range.lab` / `R07`, derives five operator secrets unique to this
clone, and reboots into its own promotion. Everything after that is unattended.

**The master secret is never written to the VM.** Only derived values land there,
and a derived value reveals neither the master nor any peer's secrets.

Add `-WhatIf` to see the derived identity without touching anything.

### Step 4 — Recover credentials any time
```powershell
.\Get-RangeCloneSecret.ps1 -CloneId 07
.\Get-RangeCloneSecret.ps1 -All 30 -AsCsv | Set-Content C:\secure\range-keys.csv
```
One master secret recomputes any clone's credentials — no per-VM bookkeeping.
Run this on the **admin box**, never on a participant VM. Treat the output as
answer-key material.

### Per-clone identity

| Item | Value |
|---|---|
| Computer name | `RANGE<nn>-DC01` |
| Domain / NetBIOS | `r<nn>.range.lab` / `R<nn>` |
| Domain SID, `krbtgt` | unique — generated by that clone's own promotion |
| Administrator, DSRM, break-glass, analyst, hidden-admin passwords | derived per clone |

**Seeded credentials (`svc_mssql:Summer2024` etc.) are identical across clones by
design.** They are meant to be cracked; a student who reuses them against a peer
has still exercised the technique and only skipped rediscovery. Set
`PerCloneSeedSuffix` if rediscovery must count for scoring.

---

## 6. Verify

```powershell
.\Test-RangeConfig.ps1 -ShowControl
```

`[live]` checks read the running subsystem — can lsass actually be opened, is the
RDP listener really NLA-free, what does the KDC actually allow. Every result
carries a NIST/CIS control ID, so the output doubles as the scoring baseline.

**Phase 1 baseline (verified on hardware 2026-09-06): 0 FAIL.** Expect some N-A
and WARN rows; those are documented, not defects:

| Row | Why |
|---|---|
| Event-log channel size | F38 — accepted deviation; not settable by any supported mechanism on 2025 |
| HiveNightmare hive DACLs | kernel holds the hives open; the VSS shadow copy is the exploitable artifact |
| PowerShell v2 | payload removed on 2025, needs Windows Update |
| NTLMv1 | removed in 2025 — a config finding, not an exploit |
| Unconstrained delegation | set on a user; coercion needs a computer account (F14) |

For a class build, also confirm **cross-VM** isolation — this is the real F16 test:
- forge a golden ticket on clone A, confirm clone B **rejects** it
- `Get-ADUser krbtgt -Properties objectSid` differs between clones
- `nltest /dsgetdc:r07.range.lab` resolves unambiguously with peers online

Cut the golden image only after `READY.txt` exists **and** you have logged in as
`analyst` to prove it.

---

## 7. When you cannot log in

Work down. Full detail in [BREAK-GLASS.md](BREAK-GLASS.md).

1. **Revert the snapshot.** Fastest and cleanest.
2. **`analyst`** — the keeper re-asserts it every boot.
3. **`rangebreak`** — visible at the sign-in screen.
4. **Accessibility shell** — Win+U or Shift x5 for a SYSTEM prompt, then
   `C:\range-fix.cmd` (role-aware: repairs Kerberos etypes, clears lockout,
   rebuilds `analyst`).
5. **Seeded `*-backup` admins** — only exist if Phase 3 completed.
6. **DSRM** — `bcdedit /set safeboot dsrepair`, log in as `.\Administrator`.
7. **Windows RE offline registry edit.**

**Diagnostic shortcut:**

| Symptom | Meaning |
|---|---|
| Every domain account fails on a DC | Kerberos etypes pinned to RC4-only — see BREAK-GLASS |
| `analyst` works, `Administrator` does not | Administrator's password is `LocalAdminAutoLogonPass` |
| `*-backup` accounts missing | Phase 3 never completed |
| Nothing works, no accessibility shell | `AccessibilityShell = $false`, or the build died in Phase 1 |

```powershell
Get-Content C:\ProgramData\CyberRange\keeper.log -Tail 30
Get-Content C:\ProgramData\CyberRange\logs\rangebuild-*.log -Tail 60
```

---

## 8. Tearing down

```powershell
.\Reset-CyberRange.ps1            # dry run
.\Reset-CyberRange.ps1 -Execute   # then type TEARDOWN
```

Re-hardens the machine and removes accounts, persistence, shares and AD attack
paths. It **cannot** undo DC promotion, exposed credentials, or missed patches.
If the box is going back to anything that matters, rebuild it.

---

## 9. Do not

- **Hand out the manifest.** `C:\ProgramData\CyberRange\logs\` holds every seeded
  password in cleartext. It is the answer key. Collect it off-box.
- **Loosen ACLs to get unstuck.** Run elevated instead.
- **Snapshot the golden image before `READY.txt`** (single-VM) or **promote the
  image before cloning** (class) — the latter reintroduces F16.
- **Put `analyst` or `rangebreak` in a participant brief.**
- **Run any of this on a box with a route to a real network.**
