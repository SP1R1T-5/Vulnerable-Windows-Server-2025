# GRC Control Map & Scenario Gap Analysis

Purpose: ground every intentional misconfiguration in a **published control**, so
the blue team's remediation is graded against a real baseline instead of an
instructor's opinion, and so the range can defend its own pedagogy in a course
syllabus or accreditation review.

_Last updated: 2026-09-03. Companion to
[VERIFICATION-REPORT-2026-09-03.md](VERIFICATION-REPORT-2026-09-03.md)._

---

## How to read this, and one caveat about identifiers

Three kinds of identifier appear below, and they are not equally stable:

- **NIST SP 800-53 Rev. 5 control IDs** (`AC-6`, `AU-12`, …) — stable, cite directly.
- **CIS Controls v8/v8.1 safeguard numbers** (`4.8`, `5.4`, …) — stable, cite directly.
- **CIS Benchmark recommendation numbers and DISA STIG V-IDs** — these renumber
  between benchmark and STIG releases. This document therefore names the
  **setting** (the Group Policy path / registry value), which is stable and
  greppable, and deliberately does **not** invent recommendation numbers.

> **DECIDED 2026-09-03 (design session):** the **CIS Microsoft Windows Server
> Benchmark** governs blue-team scoring. NIST SP 800-63B is recorded as a
> documented deviation and taught as the framework conflict (see the note under
> Domain Policy), not used for grading. **Still open:** which benchmark *release*.
> See [IMPROVEMENT-PLAN.md](IMPROVEMENT-PLAN.md) decision D4.

> **Operator task before first delivery:** pin one baseline version — e.g.
> *CIS Microsoft Windows Server 2022 Benchmark* (the mature one; a 2025 benchmark
> may not be final) and the current *Microsoft Windows Server STIG* — then fill the
> `Baseline ID` column below from that exact release. Record the version in
> HANDOFF.md. Grading against a moving target is the single easiest way to lose a
> protest in a competition.

Authoritative sources this range should cite:

| Source | Use |
|---|---|
| NIST SP 800-53 Rev. 5 | Control catalogue; the spine of the map below |
| NIST SP 800-53A Rev. 5 | Assessment procedures — how a control is *tested*, which is exactly what the blue team must do |
| NIST SP 800-171 Rev. 3 | If any scenario involves CUI; maps cleanly onto 800-53 |
| NIST SP 800-63B | Modern password guidance — see the conflict note under Domain Policy |
| NIST SP 800-61 | Incident handling lifecycle for the IR portion |
| NIST SP 800-115 | Technical assessment methodology for the red-team portion |
| CIS Controls v8.1 + CIS Microsoft Windows Server Benchmark | Safeguards and the concrete hardening settings |
| DISA Windows Server STIG (DoD Cyber Exchange) | Government-mandated settings; the strictest of the three |
| NSA/ACSC, *Detecting and Mitigating Active Directory Compromises* (2024) | **Best single anchor for the `dc\*` scenarios** — covers Kerberoasting, AS-REP roasting, AD CS ESC1–ESC8, unconstrained delegation, GPP passwords, DCSync, MachineAccountQuota |
| CISA Known Exploited Vulnerabilities catalogue | Justifies the CVE-repro choices (PrintNightmare CVE-2021-34527 is KEV-listed; confirm the others against the current catalogue) |
| Microsoft Enterprise Access Model / *Securing Active Directory* | The tiering model the range currently has no answer for (gap G9) |

---

## Machine-level misconfigurations

| Script / setting | Control basis | Baseline ID |
|---|---|---|
| **`10` Windows Update disabled** (`wuauserv`/`WaaSMedicSvc`/`UsoSvc` Start=4) | NIST **SI-2** Flaw Remediation, **CM-3**; CIS Control **7.3** Automated OS Patch Management | _pin_ |
| **`10` Defender disabled / removed** | NIST **SI-3** Malicious Code Protection, **SI-4**; CIS Control **10.1**, **10.7** | _pin_ |
| **`20` WDigest `UseLogonCredential=1`** | NIST **IA-5(1)**, **SC-28** Protection at Rest; CIS Benchmark *MS Security Guide → WDigest Authentication = Disabled* | _pin_ |
| **`20` `NoLmHash=0`** | NIST **IA-7**, **SC-13**; *Network security: Do not store LAN Manager hash value on next password change = Enabled* | _pin_ |
| **`20` `LmCompatibilityLevel=0`** | NIST **IA-7**, **SC-13**; *Network security: LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM* | _pin_ |
| **`20` `RestrictAnonymous`/`RestrictAnonymousSAM=0`, `EveryoneIncludesAnonymous=1`** | NIST **AC-3**, **AC-14**; *Network access: Do not allow anonymous enumeration of SAM accounts and shares = Enabled* | _pin_ |
| **`20` `CachedLogonsCount=50`** | NIST **AC-3**, **IA-5**; *Interactive logon: Number of previous logons to cache = 4 or fewer* | _pin_ |
| **`20` autologon + cleartext `DefaultPassword`** | NIST **IA-5(1)(c)** no unencrypted static authenticators, **AC-2**; *MSS: (AutoAdminLogon) Enable Automatic Logon = Disabled* | _pin_ |
| **`20` Kerberos `SupportedEncryptionTypes=4` (RC4)** | NIST **SC-13** cryptographic protection; *Network security: Configure encryption types allowed for Kerberos = AES128/AES256 only* | _pin_ |
| **`30` UAC off** (`EnableLUA=0`, consent prompts 0) | NIST **AC-6(2)**, **AC-6(9)**, **CM-7**; *User Account Control: Run all administrators in Admin Approval Mode = Enabled* | _pin_ |
| **`30` `LocalAccountTokenFilterPolicy=1`** | NIST **AC-6**, **AC-17**; *MS Security Guide → Apply UAC restrictions to local accounts on network logons = Enabled* | _pin_ |
| **`30` LSA PPL off (`RunAsPPL=0`)** | NIST **SC-39** Process Isolation, **SI-3**; *Configure LSASS to run as a protected process = Enabled with UEFI Lock* | _pin_ |
| **`30` Credential Guard / VBS off** | NIST **IA-2**, **SC-39**; *Turn On Virtualization Based Security = Enabled* | _pin_ |
| **`40` SMB1 enabled** | NIST **CM-7** Least Functionality, **SC-8**; CIS Control **4.8**; SMBv1 must be disabled | _pin_ |
| **`40` SMB signing off** | NIST **SC-8(1)** Transmission Integrity, **SC-23**; *Microsoft network server/client: Digitally sign communications (always) = Enabled* | _pin_ |
| **`40` insecure guest logons enabled** | NIST **IA-2**, **AC-3**; *Enable insecure guest logons = Disabled* | _pin_ |
| **`40` null sessions / null-session pipes & shares** | NIST **AC-3**, **AC-14**; *Network access: Restrict anonymous access to Named Pipes and Shares = Enabled* | _pin_ |
| **`40` NTLM min client/server security = 0** | NIST **SC-8**, **SC-13**; *Network security: Minimum session security for NTLM SSP = Require NTLMv2 + 128-bit* | _pin_ |
| **`40` firewall off, all profiles** | NIST **SC-7** Boundary Protection, **CM-7**; CIS Control **4.4** Firewall on Servers; *Windows Firewall: <profile>: Firewall state = On* | _pin_ |
| **`50` RDP NLA off + `SecurityLayer=0`** | NIST **IA-2**, **SC-8**, **AC-17**; *Require user authentication for remote connections by using Network Level Authentication = Enabled* | _pin_ |
| **`50` WinRM unencrypted + Basic + CredSSP + `TrustedHosts=*`** | NIST **SC-8**, **IA-5**, **AC-17(2)**; *Allow unencrypted traffic = Disabled*, *Allow Basic authentication = Disabled* | _pin_ |
| **`50` ExecutionPolicy Unrestricted** | NIST **CM-7(1)**, **SI-7** Software Integrity; CIS Control **2.5**/**2.7** | _pin_ |
| **`60` PowerShell script-block / module logging + transcription off** | NIST **AU-2**, **AU-3**, **AU-12**; CIS Control **8.2**, **8.5**; *Turn on PowerShell Script Block Logging = Enabled* | _pin_ |
| **`60` `ProcessCreationIncludeCmdLine_Enabled=0`** | NIST **AU-3(1)** Additional Audit Information; *Include command line in process creation events = Enabled* | _pin_ |
| **`60` event logs shrunk to 1 MB** | NIST **AU-4** Audit Storage Capacity, **AU-11** Retention; CIS Control **8.3**, **8.10** | _pin_ |
| **`60` Sysmon disabled** | NIST **SI-4** System Monitoring, **AU-12**; CIS Control **8.5**, **13.1** | _pin_ |
| **`70` SNMP with `public` community** | NIST **IA-5**, **CM-7**, **SC-8**; CIS Control **4.8** | _pin_ |
| **`70` `C:\Public` + `SYSVOL$` share, Everyone:Full** | NIST **AC-3**, **AC-6**; CIS Control **3.3** Configure Data Access Control Lists | _pin_ |
| **`70` PowerShell v2 engine enabled** | NIST **CM-7**, **AU-12** (v2 bypasses script-block logging); CIS Control **4.8** | _pin_ |
| **`75` PrintNightmare Point-and-Print** | CVE-2021-34527 (**CISA KEV**); NIST **SI-2**, **CM-7**; *Point and Print Restrictions = Enabled* | _pin_ |
| **`75` HiveNightmare hive ACLs + VSS** | CVE-2021-36934; NIST **AC-3**, **AC-6**, **SC-28** | _pin_ |
| **`80` persistence (service / task / run key / startup / Winlogon Shell)** | NIST **CM-7**, **SI-4**, **SI-7**; CIS Control **8.5**, **13.1**; MITRE ATT&CK **T1543.003**, **T1053.005**, **T1547.001** | _pin_ |
| **`90` hidden local admins, hidden from sign-in** | NIST **AC-2** Account Management, **AC-2(3)**, **AC-6(5)**; CIS Control **5.1**, **5.4** | _pin_ |

## Domain / Active Directory scenarios

Primary anchor for this whole block: **NSA/ACSC, *Detecting and Mitigating Active
Directory Compromises* (2024)** — every technique below appears in it by name,
with both the detection and the mitigation. That makes it the right citation for a
government-recommended framing.

| Script / setting | Control basis |
|---|---|
| **`dc/10` Kerberoastable SPN accounts, weak passwords, RC4** | NIST **IA-5**, **SC-13**, **AC-6**; NSA/ACSC *Kerberoasting*. Correct remediation is a **gMSA**, not a longer password — see gap G9 |
| **`dc/10` AS-REP roastable (no pre-auth)** | NIST **IA-2**, **IA-5**; NSA/ACSC *AS-REP Roasting* |
| **`dc/10` reversible encryption** | NIST **IA-5(1)(c)**; *Store passwords using reversible encryption = Disabled* |
| **`dc/10` password in `description`** | NIST **IA-5(1)(c)**, **AC-3**; CIS Control **3.3** |
| **`dc/10` `helpdesk` in Account/Server Operators** | NIST **AC-6** Least Privilege, **AC-6(7)**; CIS Control **5.4**, **6.8** |
| **`dc/20` AD CS ESC1 template** | NIST **SC-17** PKI Certificates, **IA-5(2)**, **AC-6**; NSA/ACSC *AD CS misconfigurations*; SpecterOps *Certified Pre-Owned* |
| **`dc/30` DCSync rights to a low-priv user** | NIST **AC-6**, **AC-3(7)**, **AU-6**; NSA/ACSC *DCSync* |
| **`dc/30` GenericAll on Domain Admins** | NIST **AC-6**, **AC-3**; CIS Control **6.8** |
| **`dc/30` unconstrained / constrained delegation** | NIST **AC-6**, **IA-2**; NSA/ACSC *Kerberos delegation* |
| **`dc/30` `ms-DS-MachineAccountQuota = 10`** | NIST **AC-6**, **CM-6**; NSA/ACSC *MachineAccountQuota* → set to 0 |
| **`dc/40` GPP `cpassword` in SYSVOL** | MS14-025; NIST **IA-5(1)(c)**, **AC-3**; NSA/ACSC *GPP passwords* |
| **`dc/40` weak domain password policy** | NIST **IA-5(1)**, **AC-7** Unsuccessful Logon Attempts; CIS Benchmark §1.1 *Password Policy*, §1.2 *Account Lockout Policy* |
| **`dc/50` hidden Domain Admins** | NIST **AC-2**, **AC-2(3)**, **AC-6(5)**; CIS Control **5.1**, **5.3**, **5.4** |

### A deliberate framework conflict worth teaching, not hiding

`dc/40-gpo-legacy.ps1` sets `MaxPasswordAge = 0` (never expires) and complexity
off. CIS and the DISA STIG both flag *both* as findings. **NIST SP 800-63B does
not**: it deprecates composition rules and scheduled rotation, and prescribes
length plus screening against breached-password lists instead. So the "correct"
remediation differs depending on which authority the student is being graded
under.

That is an excellent GRC lesson — control frameworks disagree, and the assessor
has to state which one applies — but only if it is **deliberate and documented**.
Decide now which baseline governs scoring, write it in the scenario brief, and
accept the other as a documented deviation. If it is left implicit, the blue team
gets marked down for following current federal guidance.

---

## Scenario gaps (ranked by impact on the stated learning objectives)

The range's stated objectives are configuration management, vulnerability
management, incident response, and competition tradecraft. Measured against those,
the technical misconfiguration coverage is strong and the **governance and
measurement layer is essentially absent**.

### G1 — RESOLVED 2026-09-03, and it changed shape rather than closing
The topology decision is made: **one VM per participant, all on a shared range
LAN, and the lateral-movement targets are other participants' VMs.**

That answers the original complaint. Relay (SMB signing off),
`LocalAccountTokenFilterPolicy`, NTLM downgrade, WinRM/RDP lateral movement,
delegation coercion and BloodHound session edges are **not inert** — the second
host is another student's box. The register (WP1) tags each technique
**Local / Peer / Inert** so nobody grades a genuinely inert one as an exploit.

What replaces G1 is bigger: **the range is now multi-tenant and the build was not
designed for that.** The image is cloned *after* DC promotion, so every clone
shares `krbtgt`, the domain SID and every NT hash — a golden ticket forged on one
box authenticates to all of them; every clone also claims the same domain and
NetBIOS name on one segment; and autologon makes each participant a Domain Admin
who can read the answer key that unlocks every peer.

**See [IMPROVEMENT-PLAN.md](IMPROVEMENT-PLAN.md)** — findings F16–F22 and work
package WP2. Do not cut and distribute a golden image before WP2 lands.

### G2 — No advanced audit policy scenario (the biggest single content gap)
`60-logging-visibility.ps1` reduces logging by registry and shrinks logs, but never
touches the **advanced audit policy subcategories** — which is where CIS and the
STIG place dozens of requirements and where a blue team actually remediates
**AU-2/AU-12**. A deliberately-wrong `auditpol` state (logon/logoff, object
access, privilege use, DS access, credential validation all off) would add a whole
graded domain for near-zero build cost, and is the natural precondition for any IR
exercise. Capture the pre- and post-state via `auditpol /backup`.

### G3 — No detection surface and nowhere for logs to go — now solvable (2026-09-03)
No Windows Event Forwarding / collector, no Sysmon baseline to *restore*, no SIEM
target. NIST **AU-6**, **SI-4**; CIS Control **8.9** Centralize Audit Logs, **13.1**.
The blue team has nothing to build detection on, so "IR" collapses into local log
reading.

**Changed by decision D6:** a range-administrator box now sits on the subnet and can
serve as the collector. Two caveats the implementing session must know:

- **WEF will not work the usual way.** After WP2 each clone is its own forest, so a
  source-initiated subscription has no shared Kerberos realm to authenticate with.
  The workable route is the admin box **pulling** over the deliberately-open WinRM,
  using each clone's derived local credential (WP2). Real WEF would need certificate
  authentication issued per clone.
- **This collection is for scoring and adjudication, not for the students.** They do
  not build or own it, so it does not by itself satisfy CIS 8.9 as a *taught*
  control. A blue-team-owned centralization exercise is separate scope.

Spec: **WP5** in [IMPROVEMENT-PLAN.md](IMPROVEMENT-PLAN.md).

### G4 — No measurable baseline, so remediation cannot be scored (**highest GRC priority**)
The manifest CSV is a prose changelog, not a control-mapped, machine-checkable
baseline. There is no "expected secure state" artifact and no way to re-score a
host after the blue team works on it — which is the core of the configuration- and
vulnerability-management objectives.

**Fix:** add a `ControlIds` column to `Write-RangeManifest` (populated from the
table above), and ship a `Test-RangeCompliance.ps1` that re-reads every setting
and emits pass/fail per control. That single change turns the range from a
demonstration into an assessable exercise, and it maps directly to NIST **SP
800-53A** assessment procedures. Consider aligning the output with **PowerSTIG**
or an OpenSCAP/SCAP datastream so scoring uses a recognised tool rather than a
bespoke script.

### G5 — No sensitive-data scenario
`C:\Public` (Everyone:Full) contains only a README. Plant synthetic PII/CUI —
clearly marked as synthetic — and the range gains data classification, ACL
remediation, and IR blast-radius scoping. NIST **AC-3**, **SC-28**, **MP-4**; CIS
Control **3.3**, **3.11**; the whole of 800-171 if CUI framing is used.

### G6 — No backup or recovery scenario
Nothing exercises **CP-9**/**CP-10** or CIS Control **11**, despite the range
seeding five accounts named `*-backup`. Also directly relevant to your break-glass
requirement: a documented, tested restore path *is* the outermost break-glass
layer. Add VSS/`wbadmin` state, a broken or absent backup as a finding, and a
restore exercise.

### G7 — Vulnerability management is thin
"Updates off" is the only vulnerability content, so a credentialed Nessus/OpenVAS
scan returns configuration findings and essentially no software CVEs. NIST
**RA-5**, **SI-2**; CIS Control **7.1–7.4**. Adding one or two intentionally
outdated, offline-installable third-party applications would make scan triage,
prioritisation (CVSS/EPSS/KEV), and patch verification real.

### G8 — No account-lifecycle artifacts
No dormant accounts with stale `lastLogonTimestamp`, no accounts past a
password-age threshold, no disabled-but-still-privileged or orphaned accounts.
CIS Control **5.3** Disable Dormant Accounts; NIST **AC-2(3)**. Cheap to seed by
back-dating attributes, and it exercises access review — a GRC activity the range
currently does not touch at all.

### G9 — No privileged-access tiering, so correct remediation has nowhere to land
`Protected Users`, Authentication Policy Silos, and the Microsoft Enterprise Access
Model are unused. Without them the *right* answer to Kerberoasting (a **gMSA**),
to credential theft (Protected Users), and to over-privilege (a tier model) cannot
be demonstrated — students learn to find the problem but not to fix it properly.
NIST **AC-6**, **IA-2(1)**; CIS Control **5.4**, **6.5**.

### G10 — No incident-response narrative
Persistence exists, but there is no initial-access story, no timeline, and no
attacker artifacts with coherent timestamps — so there is no root cause to find
and the IR exercise has no answer. NIST **SP 800-61**; CIS Control **17**. Seed a
plausible chain (phished credential → RDP logon → tooling dropped → persistence
installed) with consistent event times.

### G11 — No GRC deliverable scaffolding
For a course with a GRC emphasis, the student output should include a risk
register, an SSP-style control statement, and a **POA&M** with prioritised,
resourced remediation. Nothing in the repo scaffolds those, so the GRC dimension
currently lives only in the instructor's head. Add templates under `docs/` and
grade against them.

---

## Suggested implementation order

Superseded by the sequenced work packages in
[IMPROVEMENT-PLAN.md](IMPROVEMENT-PLAN.md) §3–§4, which carry the specs. The gap →
work-package mapping:

| Gap | Work package |
|---|---|
| G4 | **WP1** — finding register + `Test-RangeCompliance.ps1` (do first) |
| G1 | **WP2** — clone identity & first-boot personalization |
| G2, G3 | **WP5** — advanced audit policy + restorable Sysmon config |
| G8 | **WP6** — account lifecycle and realistic noise |
| G10 | **WP7** — IR narrative and timeline |
| G5 | **WP8** — sensitive data, shares and ACL depth |
| G7 | **WP9** — vulnerability-management content |
| G11 | **WP10** — GRC deliverable scaffolding |
| G6 | **WP11** — operations runbook (backup/restore scenario) |
| G9 | **WP13** — privileged-access tiering (gMSA, Protected Users, tier OUs) |
