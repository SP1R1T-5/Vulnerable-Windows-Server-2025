# Windows Server 2025 Cyber Range Builder

Turns a fresh **Windows Server 2025** VM into an **intentionally vulnerable**
domain controller for a university **red-vs-blue** lab. It teaches configuration
management, vulnerability management, incident response, and the attack/defense
tradecraft used in national collegiate cyber competitions.

> **FOR ISOLATED, AUTHORIZED EDUCATIONAL USE ONLY.**
> This build deliberately weakens the host. Run it only on a lab VM with **no
> production data** and **no unrestricted internet path**. It refuses to run
> until you set `Confirmed = $true` in `config\range.config.psd1`.

---

## Three steps

Run them in order, on a fresh, standalone Server 2025 VM you have snapshotted.
Each one prompts to continue into the next, or use `-Auto` to chain them.

```powershell
.\Stage-CyberRange.ps1     # 1. Build the domain.        Nothing is weakened.
.\Setup-CyberRange.ps1     # 2. Apply the misconfigs.    This is the range.
.\Test-RangeConfig.ps1     # 3. Verify.  -Repair to fix drift.  Optional.
```

Lost your place? This prints the one command to run next, and changes nothing:

```powershell
.\Test-RangeConfig.ps1 -Next
```

**Full instructions, and what to do when something breaks:
[docs/USER-GUIDE.md](docs/USER-GUIDE.md)** - section 9 is the troubleshooting
record from the 2026-09-07 hardware build.

| | What it does | Safe to re-run? |
|---|---|---|
| **Stage** | Stages the repo to `C:\CyberRange`, runs the safety gates, provisions your operator account, installs AD DS (plus AD CS and FS-SMB1, which need the reboot to settle), promotes the host into its own forest, and creates the OU tree, staff and service accounts. **Reboots once and resumes itself.** | Yes |
| **Setup** | Every intentional misconfiguration: frozen updates, Defender neutered, UAC/LSA/VBS off, SMB1 with signing off, RDP without NLA, WinRM unencrypted, logging blinded, legacy services, CVE artifacts, persistence beacons — then the AD attack paths (Kerberoast, AS-REP, ESC1, DCSync, delegation, GPP cpassword, hidden domain admins). Reboots at the end. | Yes |
| **Test** | Checks every control and reports PASS / FAIL / WARN / N-A with NIST/CIS mappings. `-Repair` fixes what has drifted. Changes nothing otherwise. | Yes |

Plus one utility, kept separate because it is not part of building a range:

```powershell
.\Reset-CyberRange.ps1     # Teardown in place. Dry run by default.
```

**Why structure first, then break it?** Promotion on an already-weakened box —
no firewall, no UAC, downgraded LSA — is fragile, and was the source of the
lockouts this project spent a long time fixing. Stage builds a small, ordinary,
*working* domain. Setup then breaks it on purpose. If Setup goes wrong, you still
have a healthy DC and a working login.

---

## Layout

```
Stage-CyberRange.ps1           STEP 1: domain structure. Nothing weakened.
Setup-CyberRange.ps1           STEP 2: every misconfiguration. This is the range.
Test-RangeConfig.ps1           STEP 3: verify (-Repair to fix drift).
Reset-CyberRange.ps1           Teardown in place (dry run by default).

config\range.config.psd1       All toggles, credentials, beacon target, DC settings.
modules\RangeControls.psm1     THE CONTROL TABLE -- every misconfiguration, declared once.
modules\RangeCommon.psm1       Logging, CSV manifest, safety guard, helpers.

scripts\preflight.ps1          Safety gates + operator account   (Stage runs it)
scripts\operator-account.ps1   Provisions the account you log in as
scripts\operator-keeper.ps1    Boot task: re-asserts that account every restart
scripts\directory.ps1          OUs, groups, staff and service accounts
scripts\ad-users-weaponise.ps1 Kerberoast / AS-REP / reversible / pw-in-description
scripts\ad-certificates-esc1.ps1  Enterprise CA + the ESC1 template
scripts\ad-acl-delegation.ps1  DCSync, GenericAll, unconstrained/constrained delegation
scripts\ad-gpo-legacy.ps1      GPP cpassword in SYSVOL + spray-friendly password policy
scripts\ad-hidden-admins.ps1   Hidden *-backup domain admins
scripts\dc-security-gpo.ps1    Pushes the downgrades into the Default DC Policy (F33)
```

Every run writes a timestamped log **and** an applied-changes CSV manifest to
`C:\ProgramData\CyberRange\logs\`. The manifest is the instructor answer key.

### One control, one definition

Every intentional weakness is declared **once**, in `modules\RangeControls.psm1`:
its intended value, its NIST/CIS/CVE mapping, how to check it (registry, or a
live probe of the running subsystem), how to revert it, and *why it is the way it
is on Server 2025*. Three thin verbs act on that table:

| Verb | Used by |
|---|---|
| apply  | `Setup-CyberRange.ps1` |
| check  | `Test-RangeConfig.ps1` (and `-Repair` = check → apply → re-check) |
| revert | `Reset-CyberRange.ps1` |

**Adding or changing a control is one edit, in one file.** The build cannot apply
a control one way and the checker test it another, because there is only one
definition of it.

---

## Before you start

1. **A VM you can snapshot.** Not a box you cannot roll back.
2. **Windows Server 2025**, freshly installed, **standalone — never domain-joined.**
   Stage refuses on a domain member: it promotes a standalone server into its
   *own* new forest, which a member can never do.
3. **Isolated networking.** The build disables the firewall on every profile,
   enables SMB1 and drops NLA.
4. **An elevated PowerShell.** The single most common cause of confusing failures.
5. If the repo came from a share or USB:
   `Get-ChildItem -Recurse <repo> | Unblock-File`

Then edit `config\range.config.psd1`:

- `Confirmed = $true`
- `LocalAdminAutoLogonPass` — **this becomes the Administrator password**, and is
  deliberately exposed in cleartext in the registry as the teaching artifact
- `Analyst.Password` — **your operator login.** Record it off-box.
- `DC.SafeModePassword` — DSRM. Record it off-box.
- `DC.DomainName` / `DC.NetbiosName`, and `BeaconHost` (leave at `192.0.2.1`)

The build refuses to run while any of those still holds its shipped example
value. `-Force` overrides, for a deliberate off-network dry run.

> **Building more than one VM?** Build each from scratch — run the three steps on
> each fresh VM. Do not clone a promoted DC: every clone would share `krbtgt` and
> the domain SID, so a golden ticket forged on one student's VM would work on all
> of them.

---

## What each part does

| Category | Teaches |
|---|---|
| `updates-defender` | Frozen patch level; Defender neutralized (or the feature removed) |
| `credential-exposure` | WDigest plaintext, LM/NTLMv1, anonymous SAM, autologon |
| `uac-lsa-vbs` | UAC off; LSASS PPL, Credential Guard, VBS disabled |
| `smb-network` | SMB1 on, signing off (relay), null sessions, firewall off |
| `rdp-winrm` | RDP without NLA; WinRM unencrypted + Basic + CredSSP |
| `logging-visibility` | PowerShell logging off, tiny event logs, Sysmon killed |
| `legacy-services` | SNMP `public`, TFTP, PSv2 engine, over-shared folders |
| `cve-repro` | PrintNightmare (Point-and-Print) + HiveNightmare ACLs |
| `persistence` | Service / schtask / run-key / startup / Winlogon beacons |
| `ad-users-weaponise` | Kerberoast + AS-REP fodder, reversible encryption, pw-in-description |
| `ad-certificates-esc1` | Enterprise CA + ESC1 certificate template |
| `ad-acl-delegation` | DCSync, GenericAll, unconstrained/constrained delegation |
| `ad-gpo-legacy` | GPP `cpassword` in SYSVOL, spray-friendly password policy |
| `ad-hidden-admins` | Hidden `*-backup` domain admins |
| `dc-security-gpo` | Pushes SMB-signing / NoLMHash / log-size downgrades into the Default Domain Controllers Policy so they survive `gpupdate` (F33) |

Target one category at a time on a built box:

```powershell
.\Setup-CyberRange.ps1 -Only smb-network        # re-apply one category
.\Test-RangeConfig.ps1 -Repair -WhatIf          # what has drifted?
.\Test-RangeConfig.ps1 -Repair -Only smb-network
```

## Getting back in

Recovery layers, in order — full detail in [docs/BREAK-GLASS.md](docs/BREAK-GLASS.md):

1. **Revert the snapshot.** Always fastest and cleanest.
2. **Log in as `analyst`** — a permanent SYSTEM boot task re-asserts it every
   restart, so a GPO or a lockout cannot take it away from you.
3. **Win+U or Shift ×5 at the logon screen** — a SYSTEM prompt with no password.
   Type `C:\range-fix.cmd`.
4. The seeded `*-backup` admins, then DSRM, then an offline Windows RE edit.

## Key changes from the 2019 baseline

Several 2019 techniques no longer work as written on Server 2025. The control
table corrects for this and each affected control carries the reason inline;
`Test-RangeConfig.ps1` reports a known no-op as WARN rather than PASS.

- **Defender:** `DisableAntiSpyware` has been ignored since the Aug-2020
  platform update, and `Set-MpPreference` is blocked while Tamper Protection is
  on. Reliable kill = `RemoveDefenderFeature = $true` (uninstalls the feature).
- **SMB signing is now *required by default*** (client and server), so disabling
  it is a genuine downgrade. **SMB1 is not installed by default**; the client
  also blocks guest logons by default.
- **LSA PPL / Credential Guard / VBS may ship *enabled by default*.** A registry
  `0` is not enough if they were enabled with a **UEFI lock**.
- **SMBGhost (CVE-2020-0796)** affects only 1903/1909 and **Zerologon
  (CVE-2020-1472)** enforcement is permanent — both **removed** as not
  reproducible on 2025. Current AD paths (ESC1, delegation, DCSync) replace them.
- **Telnet Server** is gone; **SNMP/WMIC** moved to Features-on-Demand.
- **Kerberos DES** is effectively removed — the 2019 `SupportedEncryptionTypes=4`
  comment ("DES") was wrong; `4` is RC4-HMAC. The build sets `0x1C` (RC4 **+**
  AES): RC4-only breaks every domain logon on a 2025 DC.

## Teardown

`Reset-CyberRange.ps1` reverts every control in the table to a known-good value
and removes the range's accounts, persistence, shares and AD attack paths. It
**cannot** undo DC promotion, exposed credentials, or missed patches.

```powershell
.\Reset-CyberRange.ps1            # dry run
.\Reset-CyberRange.ps1 -Execute   # then type TEARDOWN
```

If the box is going back to anything that matters, **rebuild it** — or roll back
to the snapshot you took before building.
