# Break-Glass & Recovery Runbook

How to keep administrative access to a range VM, and how to get it back when the
build takes it away. Written after the field lockout described in
[../HANDOFF.md](../HANDOFF.md).

**Rule zero: the build is designed to be thrown away.** If a snapshot exists,
reverting is always faster, safer and more complete than any recovery below.
Everything after Layer 1 exists because someone did not take a snapshot.

---

## Why the build locked people out (history)

Three things combined. All three are fixed as of 2026-09-03 (see *What the build
now does*, below) — this section is kept because it explains the failure you may
still hit on an **older image built before that date**.

1. **`ForceAutoLogon=1` with an unverified password.** Forced autologon was
   enabled using `LocalAdminAutoLogonPass`, but nothing ever set Administrator's
   password to that value. If the image's real password differed, Windows retried
   the logon forever.
2. **No `DefaultDomainName`.** After DC promotion the local SAM is destroyed and
   `Administrator` exists only as `RANGE\Administrator`, so an unqualified
   `DefaultUserName` failed even when the password was correct — the more likely
   explanation for a box that died *during promotion*.
3. **The recovery accounts arrived far too late.** The `*-backup` admins were
   created only after promotion, but the dangerous window opened at the *first*
   reboot, with UAC, the firewall, NLA and LSA protections already gone. Between
   those two points the machine had no alternate administrator at all.

Today the build sets and validates the password, writes `DefaultDomainName`,
never writes `ForceAutoLogon`, and provisions the operator account before the
first weakening step. `Stage-CyberRange.ps1` runs `scripts\preflight.ps1` for you
and refuses to continue if a gate fails — it verifies **in source** that none of
the three has regressed.

The three-step split (2026-09-07) removes the original hazard rather than
mitigating it. The domain is now promoted while the box is still healthy, and
nothing is weakened until `Setup-CyberRange.ps1` runs afterwards — so the
"weakened, rebooting, no way in" window that caused the lockout no longer exists.

---

## Before every build — the one-minute drill

```powershell
# 1. Snapshot the VM on the hypervisor. Not optional, not skippable.

# 2. Build the domain. Stage runs the pre-flight itself: it provisions the
#    operator account, proves it authenticates, checks every gate, and stops
#    before doing anything if a gate fails.
.\Stage-CyberRange.ps1

# 3. Only then weaken it.
.\Setup-CyberRange.ps1
```

Run the pre-flight by hand only when you are diagnosing a gate failure or
repairing a box that is already built:

```powershell
.\scripts\preflight.ps1            # read-only; exits 1 and says why
.\scripts\preflight.ps1 -Apply     # provision + authenticate the account
```

Record the following **off the box** — in a password manager, not in the repo and
not on the VM:

| Item | Where it comes from |
|---|---|
| Operator account + password | `config\range.config.psd1` → `Analyst` |
| Administrator password | **= `LocalAdminAutoLogonPass`** — the build overwrites it |
| `LocalAdminAutoLogonPass` | `config\range.config.psd1` |
| `SafeModePassword` (DSRM) | `config\range.config.psd1` — **ships as a placeholder; the build refuses to run until you change it** |
| `HiddenAdminPassword` | `config\range.config.psd1` |
| Snapshot name + timestamp | Hypervisor |

> The operator account is deliberately **not** one of
> `Config.HiddenAdminAccounts`. Those are red-team loot, hidden from the sign-in
> screen and discoverable by participants. This one is visible, is yours, and
> should not appear in any scenario brief.
>
> **One account, not two.** Until 2026-09-07 there was also a `rangebreak`
> account. It was provisioned the same way, put in the same groups, un-hidden the
> same way, and read its password from the same config file — so it shared every
> failure mode with `analyst` while looking like independent insurance. `analyst`
> is strictly better, because the operator keeper re-asserts it on *every boot*.
> The layers below are the real redundancy. A VM built before that date still has
> `rangebreak`; Layer 2 works with either name.

---

## Recovery layers — work down in order

### Layer 1 — Revert the snapshot
Always first. Complete, instant, no side effects. Everything below is worse.

### Layer 2 — Log in as the operator account (`analyst`)
It is visible on the sign-in screen (the script explicitly removes it from
`SpecialAccounts\UserList`), it is a member of Administrators — or of Domain
Admins on a DC — and the operator keeper task re-asserts all of that on **every
boot**, so a stalled phase, a GPO or a lockout cannot quietly take it away.
(On a VM built before 2026-09-07, `rangebreak` also works.) Once in:

```powershell
.\scripts\preflight.ps1 -RepairAutologon
```

That removes `ForceAutoLogon`, `AutoAdminLogon` and `DefaultPassword`. Reboot.

### Layer 3 — The logon-screen SYSTEM shell (no password at all)
Applied by `Setup-CyberRange.ps1` (an IFEO `Debugger` on `utilman.exe` and
`sethc.exe`), so it is available from the first reboot after Setup — earlier than
any of the layers below. At the sign-in screen press
**Win+U**, or **Shift five times**, and you get `cmd.exe` running as SYSTEM
without authenticating.

From that prompt, type:

```
C:\range-fix.cmd
```

It is deliberately short because **clipboard paste does not work at the logon
desktop** — you have to type it. It is role-aware: on a DC it repairs the
Kerberos encryption types first (an RC4-only KDC breaks *every* domain logon, so
no amount of account repair helps), clears account lockout, and rebuilds the
operator account; on a standalone box it repairs the local account directly.

This is also a graded persistence artifact (MITRE T1546.008 / T1546.012) — the
blue team is expected to find and remove it, which is why `Config.AccessibilityShell`
exists. If it has been removed, this layer is gone.

### Layer 4 — The seeded backup admins (post-Phase 3 only)
If Setup completed, `svc-backup` / `smb-backup` / `wsus-backup` /
`iis-backup` / `adfs-backup` exist with `HiddenAdminPassword`. They are hidden
from the sign-in screen, so use **Other user** and type the name, or come in over
RDP/WinRM — both of which the build leaves wide open.

If these do not work, `Setup-CyberRange.ps1` did **not** finish. That is
diagnostic: check `READY.txt` and the build log.

### Layer 5 — DSRM (promoted DCs only)
On a DC there is no local SAM, so DSRM is the last account-based path.

1. Boot to **Directory Services Restore Mode** — `bcdedit /set safeboot dsrepair`
   from any elevated prompt, or F8 / the recovery menu.
2. Log in as `.\Administrator` with `SafeModePassword`.
3. Fix what broke, then `bcdedit /deletevalue safeboot` and reboot.

`scripts\preflight.ps1 -Apply -EnableDsrmLogon` sets `DsrmAdminLogonBehavior=2` so
DSRM works **without** rebooting into safe mode. That is a genuine weakening of
the DC — opt in knowingly and note it in the scenario brief.

### Layer 6 — Offline repair from Windows RE
No account works, no snapshot. Boot the recovery environment: **Shift + Restart →
Troubleshoot → Advanced options → Command Prompt**, or boot the install ISO and
choose *Repair your computer*.

The Windows volume is usually `D:` in RE, not `C:`. Confirm first:

```
diskpart
list volume
exit
```

**Clear the autologon loop offline** (the safest fix, and usually sufficient):

```
reg load HKLM\OFF D:\Windows\System32\config\SOFTWARE
reg delete "HKLM\OFF\Microsoft\Windows NT\CurrentVersion\Winlogon" /v ForceAutoLogon /f
reg delete "HKLM\OFF\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /f
reg delete "HKLM\OFF\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword /f
reg unload HKLM\OFF
```

Reboot. You should now reach a normal logon prompt.

**Also useful offline:** disable the resume task so the build does not immediately
re-apply itself, by renaming `D:\CyberRange` before rebooting.

> **On the utilman/sethc binary swap:** it is the classic last resort, it works,
> and it is documented in HANDOFF. Two cautions. It does not help on a **promoted
> DC** — resetting a password with `net user` targets a local SAM that no longer
> exists; use DSRM instead. And it leaves a modified system binary behind, so a
> box recovered that way must be rebuilt, never promoted to a golden image.
> Because it is an authentication bypass, use it only on a lab VM you own, and
> reimage afterwards.

### Layer 7 — Rebuild
If you are here, the image was never snapshotted and the build is unverified.
Rebuild from the base ISO and run the drill at the top of this document.

---

## What the build now does — F1–F7 applied 2026-09-03

These were proposals; they are now in the build. This section describes current
behaviour, not future work.

1. **Administrator's password is set by Setup** to `LocalAdminAutoLogonPass`
   before autologon is written. ⚠ **This means whatever you put in
   `LocalAdminAutoLogonPass` becomes the Administrator password on this VM.**
   Set it deliberately and record it off-box.
2. **`DefaultDomainName` is written** — `.` standalone, `DC.NetbiosName` on a DC.
   Because Setup now runs *after* promotion, this is written once, in the correct
   domain form, instead of being set standalone and re-run later.
3. **`ForceAutoLogon` is never written**, and is stripped if an earlier run left
   it. `AutoAdminLogon` is set to `1` only after the credential validates via
   `PrincipalContext.ValidateCredentials`; if validation fails it is set to `0`
   and the run logs an ERROR. Either way the plaintext `DefaultPassword` — the
   actual teaching artifact — stays in the registry.
4. **The operator account exists before anything is weakened** — provisioned by
   `Stage-CyberRange.ps1` before the domain is even built, and re-created as a
   domain account after promotion (which destroys the local SAM). Driven by
   `Config.Analyst`, so it needs no prompt during an unattended build.
5. **The domain is promoted while the box is still healthy.** Nothing is weakened
   until Setup runs, so promotion never has to survive a missing firewall,
   disabled UAC or a downgraded LSA.
6. **`C:\ProgramData\CyberRange` and `C:\CyberRange` are ACL-locked** to SYSTEM +
   Administrators by `Protect-RangePath`, re-asserted when Setup finalizes. Do not
   relax these — they hold every seeded password in cleartext.
7. **A step that fails does not silently continue.** Stage stops rather than
   advancing; Setup records the failure, keeps going so one broken technique does
   not cost you the range, and says so in `READY.txt`. `-Force` overrides.

### Still your job

- Set the three credentials: `LocalAdminAutoLogonPass`, `DC.SafeModePassword`,
  `Analyst.Password`. All three ship as placeholders, and the build refuses to
  run while any of them is still the shipped value (pass `-Force` only for a
  deliberate off-network dry run).
- Take the snapshot. Nothing in software can do this for you, and gate A1 says so.
- Run the build once end-to-end. Every claim above is static review only.
