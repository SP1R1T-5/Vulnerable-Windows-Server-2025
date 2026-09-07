# Windows Server 2025 Cyber Range Builder

Provisions an **intentionally vulnerable** Windows Server 2025 image (Domain
Controller capable) for a university **red-vs-blue** lab. It teaches
configuration management, vulnerability management, incident response, and the
attack/defense tradecraft used in national collegiate cyber competitions.

> **FOR ISOLATED, AUTHORIZED EDUCATIONAL USE ONLY.**
> This build deliberately weakens the host. Run it only on a lab VM with **no
> production data** and **no unrestricted internet path**. The builder refuses
> to run until you set `Confirmed = $true` in `config\range.config.psd1`.

**Target topology (decided 2026-09-03):** one VM per participant, all on a
**shared range LAN** with no route to campus or the internet. Participants'
lateral-movement targets are **each other's VMs**. That makes the range
multi-tenant — read
[docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md) before cutting or
distributing a golden image; the current clone model has a critical flaw (F16).

---

## Layout

```
Stage-CyberRange.ps1           STAGE 1: stages the repo to C:\CyberRange, then calls the engine (RUN THIS)
                               -Mode Image  = stop before promotion, for a class of clones (F16)
Setup-CyberRange.ps1           STAGE 2 (engine): runs everything, reboots + auto-resumes (runs from C:\CyberRange)
Resume-CyberRange.ps1          Manual resume when auto-resume stalls (-StatusOnly to just look)
Initialize-RangeClone.ps1      Per-clone first boot: own name, own domain, own secrets, own forest
Get-RangeCloneSecret.ps1       Instructor: recover any clone's credentials from the master secret
Test-RangeConfig.ps1           Read-only checker: verifies every misconfig is in place (PASS/FAIL/WARN/N-A)
Repair-RangeConfig.ps1         Write-enabled companion: test -> fix -> re-test
Reset-CyberRange.ps1           Teardown in place (dry run by default)
scripts\00-break-glass.ps1     Pre-flight gates + operator recovery account (RUN THIS FIRST)
config\range.config.psd1       All toggles, passwords, beacon target, DC settings
modules\RangeCommon.psm1       Logging, CSV manifest, safety guard, reg/native helpers
scripts\10..90                 Standalone (non-AD) misconfiguration categories
scripts\75-cve-repro.ps1       CVE teaching artifacts (PrintNightmare, HiveNightmare)
scripts\05-accessibility-shell.ps1  Logon-screen SYSTEM cmd (utilman/sethc IFEO): operator break-glass + T1546 artifact
scripts\dc\00..50              Domain Controller scenarios (promote, roast, ESC1, ACLs, GPP, hidden admins)
```

Every run writes a timestamped log **and** an applied-changes CSV manifest to
`C:\ProgramData\CyberRange\logs\`. The manifest is the instructor answer key and
the basis for a reset/diff.

## How to run (recommended: the one-shot)

1. Edit `config\range.config.psd1`: set `Confirmed = $true`, review `DC.*` and
   `BeaconHost`, and set the three credentials that ship as placeholders —
   `LocalAdminAutoLogonPass` (**this becomes the Administrator password**),
   `DC.SafeModePassword`, and `BreakGlass.Password`. Record them off-box.
2. **Snapshot the VM, then run the break-glass pre-flight.** It provisions and
   validates an operator recovery account and refuses to bless the build if a
   safety gate fails:
   ```powershell
   .\scripts\00-break-glass.ps1          # read-only gates
   .\scripts\00-break-glass.ps1 -Apply   # create + validate the recovery account
   ```
   See [docs/BREAK-GLASS.md](docs/BREAK-GLASS.md). The build also does this itself
   in Phase 1, but running it first means you find problems before the box is
   weakened.
3. Open an **elevated** PowerShell and run the stager:
   ```powershell
   .\Stage-CyberRange.ps1
   ```
   That's it. Stage 1 copies the repo to `C:\CyberRange` and hands off to the
   engine (`Setup-CyberRange.ps1`) from that local copy, which applies every
   misconfig, promotes the DC (if `DC.Enabled`), seeds the AD attack paths, and
   **reboots and auto-resumes on its own** (a SYSTEM scheduled task named
   `CyberRangeSetup` re-invokes the local engine). Expect ~2 reboots for a DC
   build; you don't need to log back in or re-run. (Running `Setup-CyberRange.ps1`
   directly from the share now refuses with a pointer to the stager.)
4. Done when `C:\ProgramData\CyberRange\READY.txt` appears. Hand the VM to the
   participant. The full change list is the manifest CSV in
   `C:\ProgramData\CyberRange\logs\`.

> ⚠️ **Do not clone this image yet.** The old guidance — "snapshot after
> `READY.txt`, then clone per participant" — produces finding **F16**: cloning a
> host that is *already* a promoted Domain Controller gives every participant the
> same `krbtgt` key, the same domain SID and the same NT hashes, so on the shared
> range LAN a golden ticket or pass-the-hash forged on one VM authenticates to
> every other VM. Every clone also claims the same computer, domain and NetBIOS
> name (**F17**).
>
> The fix is structural — cut the image *before* promotion and let each clone
> promote its own forest at first boot. Spec: **WP2** in
> [docs/IMPROVEMENT-PLAN.md](docs/IMPROVEMENT-PLAN.md). Until it lands, this build
> is safe to run on a **single** lab VM and unsafe to distribute.

### Targeted work on a built box (advanced)

There is no separate partial orchestrator. Use the tool that matches the job:

```powershell
.\Repair-RangeConfig.ps1 -WhatIf                 # what has drifted?
.\Repair-RangeConfig.ps1 -Only smb-network       # fix one category
.\Reset-CyberRange.ps1                           # tear the range down (dry run)
.\Resume-CyberRange.ps1                          # continue a stalled build
```

Individual category scripts still run standalone if you need to re-apply one from
scratch, e.g. `.\scripts\dc-ad-users-roast.ps1`.


## What each category does

| Script | Teaches |
|---|---|
| `10-updates-defender` | Frozen patch level; Defender neutralized (or feature removed) |
| `20-credential-exposure` | WDigest plaintext, LM/NTLMv1, anonymous SAM, autologon |
| `30-uac-lsa-vbs` | UAC off; LSASS PPL, Credential Guard, VBS disabled |
| `40-smb-network` | SMB1 on, signing off (relay), null sessions, firewall off |
| `50-rdp-winrm` | RDP without NLA; WinRM unencrypted + Basic + CredSSP |
| `60-logging-visibility` | PowerShell logging off, tiny event logs, Sysmon killed |
| `70-legacy-services` | SNMP `public`, TFTP, PSv2 engine, over-shared folders |
| `75-cve-repro` | PrintNightmare (Point-and-Print) + HiveNightmare ACLs |
| `80-persistence` | Service / schtask / run-key / startup / Winlogon beacons |
| `90-hidden-accounts` | Hidden "backup" local admins hidden from the sign-in screen |
| `00-break-glass` | *Not a misconfiguration.* Operator recovery account + safety gates |
| `dc\10-ad-users-roast` | Kerberoast + AS-REP fodder, reversible-encryption, pw-in-description |
| `dc\20-adcs-esc1` | Enterprise CA + ESC1 certificate template |
| `dc\30-acl-delegation` | DCSync, GenericAll, unconstrained/constrained delegation |
| `dc\40-gpo-legacy` | GPP `cpassword` in SYSVOL, spray-friendly password policy |

## Key changes from the 2019 baseline

Several 2019 techniques no longer work as written on Server 2025; the scripts
correct for this and log when a step is a no-op on a given build:

- **Defender:** `DisableAntiSpyware` has been ignored since the Aug-2020
  platform update, and `Set-MpPreference` is blocked while Tamper Protection is
  on. Reliable kill = `RemoveDefenderFeature = $true` (uninstalls the feature).
- **SMB signing is now *required by default*** (client and server), so disabling
  it is a genuine downgrade. **SMB1 is not installed by default** (optional
  feature); the client also blocks guest logons by default.
- **LSA PPL / Credential Guard / VBS may ship *enabled by default*.** A registry
  `0` is not enough if they were enabled with a **UEFI lock** — see the header of
  `30-uac-lsa-vbs.ps1` for clearing the UEFI variables.
- **SMBGhost (CVE-2020-0796)** affects only 1903/1909 and **Zerologon
  (CVE-2020-1472)** enforcement is permanent — both are **removed** as not
  reproducible on 2025. Current AD paths (ESC1, delegation, DCSync) replace them.
- **Telnet Server** feature is gone; **SNMP/WMIC** moved to Features-on-Demand;
  **WMIC** is deprecated (accounts now managed with `Set-LocalUser`).
- **Kerberos DES** is effectively removed — the 2019 `SupportedEncryptionTypes=4`
  comment ("DES") was wrong; `4` is RC4-HMAC, the realistic Kerberoast downgrade.

## Reset / teardown

There is no automatic revert. Use the per-run manifest CSV to review and undo
changes, or (recommended) **snapshot the VM before building** and roll back to
the snapshot between rounds.
