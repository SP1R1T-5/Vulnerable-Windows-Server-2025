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
3. **The recovery accounts arrived far too late.** The `*-backup` admins are
   created in **Phase 3**, but the dangerous window opens at the **Phase 1**
   reboot, with UAC, the firewall, NLA and LSA protections already gone. Between
   those two points the machine had no alternate administrator at all.

Today the build sets and validates the password, writes `DefaultDomainName`,
never writes `ForceAutoLogon`, and provisions the break-glass account before the
first weakening step. Run `scripts\00-break-glass.ps1` anyway — it verifies in
source that none of the three has regressed.

---

## Before every build — the five-minute drill

```powershell
# 1. Snapshot the VM on the hypervisor. Not optional, not skippable.

# 2. Read-only pre-flight. Exits 1 and refuses to bless the build if any gate fails.
.\scripts\00-break-glass.ps1

# 3. Provision the recovery account, and prove it actually authenticates.
.\scripts\00-break-glass.ps1 -Apply

# 4. Re-run the pre-flight until it prints PASS.
.\scripts\00-break-glass.ps1
```

Then, and only then, `.\Stage-CyberRange.ps1` (Stage 1 -> the engine).

Record the following **off the box** — in a password manager, not in the repo and
not on the VM:

| Item | Where it comes from |
|---|---|
| Break-glass account + password | `config\range.config.psd1` → `BreakGlass` |
| Administrator password | **= `LocalAdminAutoLogonPass`** — the build overwrites it |
| `LocalAdminAutoLogonPass` | `config\range.config.psd1` |
| `SafeModePassword` (DSRM) | `config\range.config.psd1` — **still the placeholder `S@feM0de-ChangeMe!`; change it** |
| `HiddenAdminPassword` | `config\range.config.psd1` |
| Snapshot name + timestamp | Hypervisor |

> The break-glass account is deliberately **not** one of
> `Config.HiddenAdminAccounts`. Those are red-team loot, hidden from the sign-in
> screen and discoverable by participants. This one is visible, is yours, and
> should not appear in any scenario brief.

---

## Recovery layers — work down in order

### Layer 1 — Revert the snapshot
Always first. Complete, instant, no side effects. Everything below is worse.

### Layer 2 — Log in as the break-glass account
It is visible on the sign-in screen (the script explicitly removes it from
`SpecialAccounts\UserList`) and is a member of Administrators, or of Domain Admins
on a DC. Once in:

```powershell
.\scripts\00-break-glass.ps1 -RepairAutologon
```

That removes `ForceAutoLogon`, `AutoAdminLogon` and `DefaultPassword`. Reboot.

### Layer 3 — The seeded backup admins (post-Phase 3 only)
If the build reached Phase 3, `svc-backup` / `smb-backup` / `wsus-backup` /
`iis-backup` / `adfs-backup` exist with `HiddenAdminPassword`. They are hidden
from the sign-in screen, so use **Other user** and type the name, or come in over
RDP/WinRM — both of which the build leaves wide open.

If these do not work, the build did **not** reach Phase 3. That is diagnostic:
it died during Phase 1 or promotion.

### Layer 4 — DSRM (promoted DCs only)
On a DC there is no local SAM, so DSRM is the last account-based path.

1. Boot to **Directory Services Restore Mode** — `bcdedit /set safeboot dsrepair`
   from any elevated prompt, or F8 / the recovery menu.
2. Log in as `.\Administrator` with `SafeModePassword`.
3. Fix what broke, then `bcdedit /deletevalue safeboot` and reboot.

`00-break-glass.ps1 -Apply -EnableDsrmLogon` sets `DsrmAdminLogonBehavior=2` so
DSRM works **without** rebooting into safe mode. That is a genuine weakening of
the DC — opt in knowingly and note it in the scenario brief.

### Layer 5 — Offline repair from Windows RE
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

### Layer 6 — Rebuild
If you are here, the image was never snapshotted and the build is unverified.
Rebuild from the base ISO and run the drill at the top of this document.

---

## What the build now does — F1–F7 applied 2026-09-03

These were proposals; they are now in the build. This section describes current
behaviour, not future work.

1. **Administrator's password is set in Phase 1** to `LocalAdminAutoLogonPass`
   before autologon is written. ⚠ **This means whatever you put in
   `LocalAdminAutoLogonPass` becomes the Administrator password on every clone.**
   Set it deliberately and record it off-box.
2. **`DefaultDomainName` is written** — `.` standalone, `DC.NetbiosName` on a DC.
   Phase 3 re-runs `20-credential-exposure.ps1` after promotion precisely so this
   flips to the domain form once the local SAM is gone.
3. **`ForceAutoLogon` is never written**, and is stripped if an earlier run left
   it. `AutoAdminLogon` is set to `1` only after the credential validates via
   `PrincipalContext.ValidateCredentials`; if validation fails it is set to `0`
   and the run logs an ERROR. Either way the plaintext `DefaultPassword` — the
   actual teaching artifact — stays in the registry.
4. **`00-break-glass.ps1 -Apply -FromBuild` is the first action of Phase 1**,
   before any weakening, and runs again at the start of Phase 3 on a DC (promotion
   destroys the local account). Driven by `Config.BreakGlass`, so it needs no
   prompt during an unattended build.
5. **`C:\ProgramData\CyberRange` and `C:\CyberRange` are ACL-locked** to SYSTEM +
   Administrators by `Protect-RangePath`, and re-asserted in Phase 4. Do not relax
   these — they hold every seeded password in cleartext.
6. **A phase with any failed step does not advance and does not reboot.** Fix the
   cause and re-run (steps are idempotent), or pass `-Force` to override.

### Still your job

- Set the three credentials: `LocalAdminAutoLogonPass`, `DC.SafeModePassword`,
  `BreakGlass.Password`. All three ship as placeholders.
- Take the snapshot. Nothing in software can do this for you, and gate A1 says so.
- Run the build once end-to-end. Every claim above is static review only.
