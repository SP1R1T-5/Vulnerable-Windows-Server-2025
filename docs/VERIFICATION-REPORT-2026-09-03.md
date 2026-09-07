# RANGE VERIFICATION REPORT — repo static review — pre-build — 2026-09-03

**Scope of this pass:** static/source verification of the repo at
`D:\Projects\WinServer2026CyberRange`. **No live Server 2025 VM was available**, so
every Part B item below is `NOT-RUN (no target)`. What *was* verified: all 18
PowerShell files parse clean, the config loads, and each defect below was
reproduced or confirmed by grep / ACL inspection on a Windows host.

Verdict at time of review: **DO NOT BUILD.** Three pre-flight gates were BLOCKED
in source and there was **no break-glass path at all** between Phase 1 and Phase 3.

> **STATUS UPDATE - findings F1-F7 have since been APPLIED** at the operator's
> direction. Each is marked **[FIXED]** below with what changed. F8-F15 remain
> **open and reported-only**. The build is now *believed* buildable and
> recoverable, but **nothing here has been executed on a Server 2025 VM** - the
> Part B matrix is still 31 NOT-RUN. Treat the verdict as
> **"cleared to attempt a build on a snapshotted VM"**, not "verified".

---

## PRE-FLIGHT (Part A): **BLOCKED**

| # | Check | Result |
|---|---|---|
| A1 | Snapshot exists | `NOT-RUN` — operator must confirm on the hypervisor |
| A2 | Admin pw == autologon pw | **BLOCKED** — nothing in the repo sets Administrator's password; `LocalAdminAutoLogonPass = 'Password!'` is asserted, never enforced |
| A3 | ForceAutoLogon risk | **BLOCKED** — `scripts/20-credential-exposure.ps1:40` still sets `ForceAutoLogon=1`; unchanged since the field lockout |
| A4 | Recovery account documented | **BLOCKED** — no break-glass account exists at the moment of maximum risk (F2). `SafeModePassword` is still the placeholder `S@feM0de-ChangeMe!` |
| A5 | Config sanity | **PARTIAL** — `Confirmed=$true`, `DC.*` coherent, but `BeaconHost` is wrong (F6) and passwords are still placeholders |
| A6 | Right host | `NOT-RUN` — no target |

## TECHNIQUES (Part B): 0 pass / 0 fail / **31 NOT-RUN (no target)**

Every machine-level and DC technique in the Part B matrix requires a live box.
Nothing in this pass verifies behavior. Separately, F8–F11 identify techniques
expected to be **configured-but-inert on Server 2025** — re-test them explicitly
rather than assuming the registry value implies the behavior.

---

## FINDINGS (ranked)

### F1 — **[FIXED]** BLOCKER · Lockout gate unchanged. Autologon is both unauthenticated and undomained.

`scripts/20-credential-exposure.ps1:36-40` writes `AutoAdminLogon=1`,
`DefaultUserName=Administrator`, `DefaultPassword=Password!`, `ForceAutoLogon=1`.
Two independent failure modes:

1. **Password mismatch (known).** No script sets Administrator's password, so
   unless the base image already uses `Password!`, `ForceAutoLogon=1` produces a
   failed-autologon loop.
2. **Missing `DefaultDomainName` (new — not previously identified).** `grep`
   confirms **no script anywhere sets `DefaultDomainName`**. After Phase 2
   promotion the local SAM is gone and `Administrator` exists only as
   `RANGE\Administrator`. An unqualified `DefaultUserName` plus `ForceAutoLogon=1`
   on a DC is a second, independent route to the same loop — and it matches the
   field symptom that the box died *during or after promotion*.

**Fix (all three):** set Administrator's password to `LocalAdminAutoLogonPass` in
Phase 1 *before* autologon is written; set `DefaultDomainName` (`.` pre-promotion,
`RANGE` post-promotion); and **drop `ForceAutoLogon`** — with `AutoAdminLogon`
alone, a bad password drops you at the logon screen instead of looping. The
exposed-credential teaching point is unaffected by removing it.

### F2 — **[FIXED]** BLOCKER · No break-glass account exists during the dangerous window.

Phase 1 removes UAC, the firewall, NLA and LSA protections, then reboots into
forced autologon. The **only** accounts that could rescue that state
(`90-hidden-accounts.ps1`, `dc/50-hidden-domain-admins.ps1`) do not run until
**Phase 3**. This reproduces the field report exactly ("backup admins didn't work
— Phase 3 had not run").

Compounding it: `Config.Categories.HiddenAccounts` is **dead config** — `grep`
shows it is read nowhere. `Setup-CyberRange.ps1:192` calls the local-accounts
script unconditionally, and only on the non-DC branch.

**Delivered:** `scripts/00-break-glass.ps1` plus [BREAK-GLASS.md](BREAK-GLASS.md).
Run it before every build.

### F3 — **[FIXED]** BLOCKER · The answer key is world-readable by every account the range seeds.

Verified against live Windows default ACLs:

- `C:\ProgramData\` grants `BUILTIN\Users` **ReadAndExecute + Write**, inherited.
  The manifest CSV in `C:\ProgramData\CyberRange\logs\` therefore lets any
  authenticated user read every seeded password — `dc/10:67` writes
  `pw=<plaintext>` per user, `dc/50:46` writes the Domain Admins password.
- `C:\` grants `BUILTIN\Users` **ReadAndExecute**, inherited. The staged
  `C:\CyberRange\config\range.config.psd1` — DSRM password, autologon password,
  hidden-admin password — is readable the same way.
- `READY.txt` points participants straight at the log directory.

Combined with `RestrictAnonymous=0` and `RestrictNullSessAccess=0`, the red team
can skip the entire exercise. **Fix:** `icacls /inheritance:r` the log directory
and `C:\CyberRange` down to `SYSTEM` + `Administrators`, or write the manifest
off-box. This is a scoring-integrity defect, not just hygiene.

### F4 — **[FIXED]** HIGH · Every Defender runtime toggle silently fails, and is misreported.

`scripts/10-updates-defender.ps1:45` — `Set-MpPreference @{ $k = $mp[$k] }` is a
**hashtable literal passed positionally**, not splatting (splatting requires
`@variable`). Reproduced locally:

```
A positional parameter cannot be found that accepts argument 'System.Collections.Hashtable'.
```

All seven toggles throw, and the `catch` logs them as
`"blocked (Tamper Protection?)"` — the log actively points the operator at the
wrong root cause. **Fix:** `$h = @{ $k = $mp[$k] }; Set-MpPreference @h`.
With `RemoveDefenderFeature = $false` (current config), the registry-policy block
is the only surviving mechanism and `DisableAntiSpyware` is a documented no-op on
2025 — so **Defender is probably still running** on the finished image.

### F5 — **[FIXED]** HIGH · `Invoke-RangeBuild.ps1` is documented in four places and does not exist.

README (19, 51, 54), HANDOFF (89), CHANGELOG, and `scripts/dc/00-promote-dc.ps1`
(7, 80) all reference it, including a `-Only` flag and "re-run it after
promotion." It is not in the tree. Every documented manual-recovery and
partial-run path is currently fictional — which matters directly for break-glass.
**Fix:** write it, or purge the references. Until then `Setup-CyberRange.ps1` is
the only entry point, and it cannot be run partially.

### F6 — **[FIXED]** HIGH · The beacon target contradicts its own safety comment.

`config/range.config.psd1:56` — `BeaconHost = '10.0.2.15'` annotated
`# RFC 5737 TEST-NET-1: routes nowhere real`. Wrong on both counts: `10.0.2.15` is
RFC 1918 space and the **default VirtualBox NAT guest address**; TEST-NET-1 is
`192.0.2.0/24`, as the comment block six lines above correctly states. On any
range using `10.0.0.0/8`, every clone TCP-connects to a real host every 300
seconds. **Fix:** `192.0.2.1`. (HANDOFF logs this as a "stale comment" — it is the
*value* that is wrong, and it is a containment issue, not a docs issue.)

### F7 — **[FIXED]** HIGH · Failed phases still advance the state machine.

`Setup-CyberRange.ps1:100` catches every step failure, logs `ERROR`, and returns.
`$state.Phase` is then incremented and saved unconditionally (144, 194). A Phase 1
that fails outright still reboots and proceeds to DC promotion. **Fix:** count
per-phase failures and refuse to advance past a phase that had any, unless forced.

### F8 — HIGH · ESC1 will very likely not be exploitable as built (two independent reasons).

1. **Strong certificate binding enforcement.** Since the February-2025 milestone
   of KB5014754 the KDC defaults to Full Enforcement: a certificate lacking the
   `szOID_NTDS_CA_SECURITY_EXT` SID extension is rejected for PKINIT. The cloned
   template supplies a caller-controlled UPN/SAN and no SID — precisely the case
   full enforcement blocks. The classic "request a cert as Domain Admin, then
   authenticate with it" chain therefore fails on a stock 2025 DC. To teach ESC1,
   the range must explicitly set
   `HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement = 1`
   (compatibility mode) — and that downgrade should itself be a manifest row and a
   graded blue-team finding.
2. **Duplicate template OID.** `scripts/dc/20-adcs-esc1.ps1:60-68` copies
   `msPKI-Cert-Template-OID` verbatim from the built-in `User` template. That
   attribute must be unique per template; two templates sharing one OID breaks
   template resolution at the CA. `msPKI-Private-Key-Flag` is also never copied.
   **Fix:** mint a new OID under
   `CN=OID,CN=Public Key Services,CN=Services,<config NC>`.

Treat ESC1 as **unverified and probably broken** until `certipy find -vulnerable`
returns it against a live DC.

### F9 — MEDIUM · NTLMv1 was removed in Server 2025; `LmCompatibilityLevel=0` no longer delivers it.

`scripts/20-credential-exposure.ps1:25` sets `LmCompatibilityLevel=0` to "send LM
& NTLMv1." NTLMv1 support was removed from MSV1_0 in Windows 11 24H2 / Server
2025. The README's 2019→2025 change notes catch several of these but miss this
one. Keep the setting — it is a genuine CIS/STIG finding for the blue team to
remediate — but **the downgrade attack it advertises will not work**. Verify
on-box and re-label it as a configuration-management finding rather than an
exploitable path.

### F10 — MEDIUM · RC4 Kerberos is set on principals but never enabled domain-wide.

`dc/10` stamps `msDS-SupportedEncryptionTypes=4` on the service accounts, but the
KDC's own supported-etype policy is left at default while RC4 is being
progressively disabled across the platform. If the KDC refuses RC4, no
`hashcat -m 13100` ticket is ever issued and the Kerberoast lab yields nothing.
**Fix:** set `HKLM:\SYSTEM\CurrentControlSet\Services\KDC\DefaultDomainSupportedEncTypes`
and the domain object's `msDS-SupportedEncryptionTypes` explicitly, then confirm
the ticket etype is 23 via `klist` after a `Rubeus kerberoast`.

### F11 — MEDIUM · LDAP signing / channel binding is never downgraded.

Server 2025 ships with LDAP signing required and LDAP channel binding enforced.
The range never touches `NTDS\Parameters\LDAPServerIntegrity` or
`LdapEnforceChannelBinding`, so NTLM-relay-to-LDAP — the natural partner to the
SMB-signing downgrade in `40-smb-network.ps1` — stays blocked. Both a missing
technique and a missing CIS/STIG finding for the blue team.

### F12 — MEDIUM · `dc/10` is not idempotent for the attributes that matter.

`New-RangeUser` (line 51) applies `-Spn`, `-Desc` and `-Path` **only on the create
branch**. On a re-run — including the orchestrator's own Phase-3 retry after a
partial failure — an existing user gets a password reset and nothing else, so SPNs
are never applied and Kerberoasting silently returns zero targets. **Fix:** apply
SPN / description / UAC flags on both branches.

### F13 — MEDIUM · SNMP install will fail on an isolated box, then report success.

`scripts/70-legacy-services.ps1:26-31` — `Add-WindowsCapability -Online` pulls a
Feature-on-Demand payload from Windows Update, which `10-updates-defender.ps1`
disabled two scripts earlier, on a host the README requires to be isolated.
Worse: if `Get-WindowsCapability` returns nothing the `try` still succeeds,
`$snmpInstalled` is set `$true`, and `$cap.Name` is `$null` on line 28. The
registry writes then configure a service that does not exist. **Fix:** supply
`-Source <ISO>\sources\sxs`, verify state after install instead of assuming, and
run this category before Windows Update is disabled.

### F14 — LOW · Unconstrained delegation is set on a *user*, which is not the taught attack.

`dc/30:56` sets `TrustedForDelegation` on `svc_web`. The printerbug/coercion →
TGT-capture path needs a **computer** account (or a service actually running as
that user) to receive the forwarded TGT. As built this is a BloodHound edge with
no exploit behind it. See gap G1 — it needs a second host to become real.

### F15 — LOW · Assorted

- `dc/40:76` bumps `versionNumber` on the AD object but never updates `GPT.ini` in
  SYSVOL, leaving a GPO version mismatch. Cosmetic — `Groups.xml` stays readable,
  which is the exercise.
- `scripts/80-persistence.ps1:60-61` writes `HKCU:` from a step that also runs as
  SYSTEM on resume, so the screensaver keys land in the wrong hive.
- `Setup-CyberRange.ps1:135` and `scripts/10:67` both uninstall the Defender
  feature. Harmless duplication (config currently `$false`).
- If the build dies mid-Phase-3, the `CyberRangeSetup` startup task is never
  removed and re-runs Phase 3 on every boot indefinitely.

---

## BLOCKERS / RECOMMENDATIONS — in order

1. **Establish break-glass first.** Run `scripts\00-break-glass.ps1 -Apply` and
   follow [BREAK-GLASS.md](BREAK-GLASS.md). Nothing else should be attempted until
   a validated non-Administrator admin path exists. (F2)
2. **Fix the autologon triad** — set the Administrator password, set
   `DefaultDomainName`, drop `ForceAutoLogon`. (F1)
3. **ACL the answer key** (`C:\ProgramData\CyberRange`, `C:\CyberRange`). (F3)
4. **Fix `BeaconHost` to `192.0.2.1`** before any clone exists. (F6)
5. **Fix the `Set-MpPreference` splat**, then confirm `Get-MpComputerStatus`
   really reports `RealTimeProtectionEnabled = False`. (F4)
6. **Stop advancing phases on failure.** (F7)
7. Only then run the full build on a snapshotted VM and execute the Part B matrix
   — treating F8–F11 as **expected failures until proven otherwise**.
8. Adopt a control-mapped baseline so remediation becomes measurable — see
   [GRC-CONTROL-MAP.md](GRC-CONTROL-MAP.md).
