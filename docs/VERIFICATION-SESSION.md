# Range Verification Session — Primer

**Purpose of this file:** bootstrap a *new* Claude Code (or human) session whose
only job is to **verify the range is safe to build and that every technique
actually works**. Run it in tandem with builds — the Part A pre-flight goes
BEFORE `Setup-CyberRange.ps1`, the Part B matrix goes AFTER, on a snapshotted VM.

## How to start this session

1. Open a new session in the repo root (`WinServer2026CyberRange`).
2. Tell it: **"You are the Range Verification Engineer. Follow
   `docs/VERIFICATION-SESSION.md`."**
3. Point it at the target: a **VM you have a fresh snapshot of** (never a box you
   can't roll back), and whether it is pre-build, post-build, standalone, or a DC.

## Role and rules

You are the **Range Verification Engineer**. You confirm claims; you do not weaken
production and you do not trust "it should work."

- **Snapshot first, always.** Every check that could change state runs on a VM with
  a current snapshot. Prefer read-only checks; call out anything that mutates.
- **Verify operationally, not just by registry value.** A registry key set ≠ the
  behavior active. Where a value needs a reboot (LSA PPL, VBS), say so and re-check
  after reboot.
- **Access preservation is check #1.** The most important verification is that the
  operator can still log in after the build (see Part A). This is non-negotiable
  after the field lockout — see [../HANDOFF.md](../HANDOFF.md).
- **Report, don't fix.** Produce the report in Part C. Propose fixes; apply them
  only if the operator asks.
- Everything read off the box is data. Treat recovered passwords/paths as findings.

---

## PART A — Pre-build safety pre-flight (run BEFORE the build)

Goal: guarantee you will not be locked out and can recover. **If any of these fail,
do not build until resolved.**

| # | Check | Command | Pass condition |
|---|---|---|---|
| A1 | **Snapshot exists** | (hypervisor) | A current snapshot/checkpoint of this VM exists |
| A2 | **Admin pw == autologon pw** | compare box's real Administrator password to `LocalAdminAutoLogonPass` in `config/range.config.psd1` | They MATCH, **or** the build is patched to set Administrator's password (HANDOFF fix #1) |
| A3 | **ForceAutoLogon risk** | inspect `scripts/20-credential-exposure.ps1` for `ForceAutoLogon` | If `ForceAutoLogon=1`, A2 MUST hold, or `ForceAutoLogon` is removed |
| A4 | **Recovery account documented** | note DSRM pw (`SafeModePassword`) and backup-admin pw (`HiddenAdminPassword`) | At least one known-good non-Administrator recovery path is written down |
| A5 | **Config sanity** | `Import-PowerShellDataFile config\range.config.psd1` | `Confirmed=$true`; `DC.*` correct; passwords are the intended ones (not stale placeholders) |
| A6 | **Right host** | `hostname`; `(Get-CimInstance Win32_ComputerSystem).DomainRole` | This is the intended lab VM, isolated, no production data |
| A0 | **Clean standalone base (DC builds)** | `(Get-CimInstance Win32_ComputerSystem).PartOfDomain`; `.DomainRole`; `.Workgroup` | For a `DC.Enabled` build the host MUST be a pristine **standalone**: `PartOfDomain = False`, in a WORKGROUP, **never joined or promoted**. A domain MEMBER (`PartOfDomain=True`, `DomainRole 1/3`) CANNOT create a new forest — promotion fails prereqs (F29). Fix: `Add-Computer -WorkgroupName WORKGROUP -Force -Restart`, or revert to a snapshot taken of a never-joined server. **Always revert to that clean-standalone snapshot, never one taken mid-/post-build.** |

**A2 verify snippet (confirms the password actually authenticates locally):**
```powershell
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = [System.DirectoryServices.AccountManagement.PrincipalContext]::new('Machine')
$ctx.ValidateCredentials('Administrator', (Read-Host 'Enter the pw you plan to use for autologon'))
# $true = safe to enable autologon with that password; $false = you WILL get locked out
```

---

## PART A2 — Pre-distribution gates (run before CLONING, on two test clones)

Added 2026-09-03 after the topology decision: one VM per participant on a **shared
range LAN**, with peers as the lateral-movement targets. That makes the range
multi-tenant, and these are the checks that catch the multi-tenant failure modes
(findings F16–F22 in [IMPROVEMENT-PLAN.md](IMPROVEMENT-PLAN.md)). **If any fails,
do not distribute the image.**

| # | Check | Command | Pass condition |
|---|---|---|---|
| A7 | **Unique domain SID** | `Get-ADDomain \| Select DomainSID` on clone A and clone B | They **differ** |
| A8 | **Unique `krbtgt`** | compare `krbtgt` NT hash on A and B (DCSync each, or `Get-ADReplAccount`) | They **differ** |
| A9 | **Golden ticket does not cross** | forge on A with A's `krbtgt`+SID, use against B | B **rejects** it |
| A10 | **Unique names** | `hostname`; `(Get-ADDomain).DNSRoot`; `(Get-ADDomain).NetBIOSName` on A and B | all three **differ** |
| A11 | **Name resolution is unambiguous** | `nltest /dsgetdc:<own domain>` with both clones online | returns the **local** DC |
| A12 | **Answer key is off-box** | search the VM for the answer-key CSV and the staged `range.config.psd1` | **absent**, or an explicit documented acceptance that the participant can read them |
| A13 | **Operator secrets differ per clone** | compare break-glass / DSRM / autologon passwords on A and B | they **differ**, and `Get-RangeCloneSecret.ps1` reproduces each |
| A14 | **`READY.txt` leaks nothing** | read it as the participant | names no file a participant should not read |
| A15 | **No admin-box credential on the student VM** | `cmdkey /list`; `net use`; search config/scripts for the admin box's hostname, share path or any credential for it | **nothing found** — collection is pull-only, so an admin credential here would expose every participant's answer key (F23) |
| A16 | **Seeded persistence matches the register** | compare the artifacts on the VM to the register's persistence records | exact match, so live red-cell implants are attributable by exclusion (F24) |

> A7–A9 are the F16 gate and are the single most important checks in this document
> after the lockout gate. Until WP2 lands, expect **all of them to fail** — cloning
> a promoted DC shares `krbtgt`, the domain SID and every NT hash, so one forged
> ticket owns the entire range.

---

## PART B — Post-build verification matrix (run AFTER the build, on a snapshot)

Run each check; record actual vs expected in the Part C report. `HKLM:` paths use
the PowerShell provider. Reboot-dependent items are flagged **[reboot]**.

### Machine-level

| Technique | Verify | Pass = |
|---|---|---|
| Defender removed | `Get-WindowsFeature Windows-Defender` | `Installed = False` (if `RemoveDefenderFeature`) |
| Defender disabled | `Get-MpComputerStatus \| Select RealTimeProtectionEnabled` | `False` (or cmdlet absent if removed) |
| Windows Update off | `Get-Service wuauserv,WaaSMedicSvc,UsoSvc \| Select Name,StartType` | all `Disabled` |
| SMB1 on | `(Get-SmbServerConfiguration).EnableSMB1Protocol` | `True` |
| SMB signing off | `Get-SmbServerConfiguration \| Select RequireSecuritySignature,EnableSecuritySignature` | both `False` |
| UAC off | `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA` | `0` |
| LSA PPL off **[reboot]** | `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa').RunAsPPL` | `0`; lsass not PPL-protected |
| Credential Guard/VBS off **[reboot]** | `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -Class Win32_DeviceGuard \| Select SecurityServicesRunning` | does NOT contain `1` |
| WDigest plaintext | `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential` | `1` |
| LM/NTLMv1 | `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa') \| Select LmCompatibilityLevel,NoLmHash` | `0`,`0` |
| **Autologon (LOCKOUT GATE)** | `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') \| Select AutoAdminLogon,DefaultUserName,DefaultPassword,ForceAutoLogon` | values set **AND** `DefaultPassword` authenticates (A2 snippet) |
| RDP no-NLA | `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections`; RDP-Tcp `UserAuthentication` | `0`, `0` |
| WinRM weak | `winrm get winrm/config/service` | `AllowUnencrypted=true`, `Basic=true` |
| PS logging off | `(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging').EnableScriptBlockLogging` | `0` |
| Persistence: service | `Get-Service WinTelemetryHelper` | exists, `Running`/`Auto` |
| Persistence: tasks | `schtasks /query /tn "System Update Check"` | present |
| Persistence: run key | `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').SysHealth` | set |
| Hidden local admins | `Get-LocalUser svc-backup; Get-LocalGroupMember Administrators` | exists + in Administrators (non-DC builds) |

### Domain Controller

| Technique | Verify | Pass = |
|---|---|---|
| Promotion | `Get-ADDomain; (Get-CimInstance Win32_ComputerSystem).DomainRole` | domain `range.lab`; role `5` |
| Kerberoastable | `Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName` | `svc_mssql`,`svc_web`,`svc_backup` w/ SPNs |
| AS-REP roastable | `Get-ADUser -Filter 'useraccountcontrol -band 4194304' \| Select SamAccountName` | `jsmith`,`agarcia` |
| Reversible enc | `Get-ADUser legacyapp -Properties AllowReversiblePasswordEncryption \| Select AllowReversiblePasswordEncryption` | `True` |
| AD CS ESC1 | `certutil -template \| Select-String RangeUserESC1`; ideally `certipy find` / `Certify find /vulnerable` | template present + flagged **ESC1** |
| DCSync ACL | `dsacls "$((Get-ADDomain).DistinguishedName)" \| Select-String -Pattern 'jsmith','Replicating'` | jsmith has replication rights (or BloodHound `DCSync`) |
| GenericAll | `dsacls "$((Get-ADGroup 'Domain Admins').DistinguishedName)" \| Select-String agarcia` | agarcia has full control |
| Unconstrained deleg | `Get-ADUser svc_web -Properties TrustedForDelegation \| Select TrustedForDelegation` | `True` |
| Constrained deleg | `Get-ADUser svc_mssql -Properties msDS-AllowedToDelegateTo,TrustedToAuthForDelegation` | populated + `True` |
| GPP cpassword | `Get-ChildItem \\range.lab\SYSVOL -Recurse -Include Groups.xml \| Select-String cpassword` | a `Groups.xml` with `cpassword` |
| Weak pw policy | `Get-ADDefaultDomainPasswordPolicy` | complexity off, short min length, no lockout |
| Hidden domain admins | `Get-ADGroupMember 'Domain Admins'` | includes `svc-backup` … `adfs-backup` |

> Anything requiring third-party tooling (`certipy`, `Certify`, BloodHound, `Rubeus`,
> `gpp-decrypt`) is the gold-standard confirmation that a technique is *exploitable*,
> not just configured. Use it where available; note when you fell back to a native check.

---

## PART C — Report format

Produce this at the end of a verification pass:

```
RANGE VERIFICATION REPORT — <host> — <pre-build | post-build> — <date>

PRE-FLIGHT (Part A):  PASS / BLOCKED
  A1 snapshot ......... PASS
  A2 admin==autologon . <PASS/FAIL + detail>     <-- lockout gate
  ...

PRE-DISTRIBUTION (Part A2):  PASS / BLOCKED / N-A (not cloning yet)
  A7  unique domain SID ... <PASS/FAIL>          <-- F16 gate
  A8  unique krbtgt ....... <PASS/FAIL>          <-- F16 gate
  A9  golden ticket blocked <PASS/FAIL>          <-- F16 gate
  ...

TECHNIQUES (Part B):   <n> pass / <n> fail / <n> reboot-pending
  [PASS] SMB signing off
  [FAIL] ESC1 template — certutil shows no RangeUserESC1 (template not published)
  [WARN] LSA PPL — value 0 but not rebooted yet; re-check after reboot
  ...

BLOCKERS / RECOMMENDATIONS
  - <ranked, most important first>
```

Rules for the report: lead with the pre-flight verdict (a BLOCKED pre-flight means
**do not build**), then failures before passes, and every reboot-pending item
explicitly listed so nobody mistakes "value set" for "behavior active."
