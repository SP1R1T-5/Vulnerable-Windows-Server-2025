# Improvement Plan — 2026-09-03 (design session)

**What this is.** The output of a design session held after the 2026-09-03
verification pass. It converts the open gaps (`G1`–`G11` in
[GRC-CONTROL-MAP.md](GRC-CONTROL-MAP.md)) and open findings (`F8`–`F15` in
[VERIFICATION-REPORT-2026-09-03.md](archive/VERIFICATION-REPORT-2026-09-03.md)) into
**work packages another session can implement without re-deriving the reasoning**,
and records seven new findings (`F16`–`F22`) that fall out of the topology
decision made here.

**How to use it.**

- **Build session:** pick a work package, read its *Spec*, implement it, satisfy
  its *Done when*. Each WP is self-contained — files to touch, exact behaviour,
  acceptance criteria. Update [CHANGELOG.md](../CHANGELOG.md) and
  [HANDOFF.md](../HANDOFF.md) when a WP lands.
- **Verification session:** follow [VERIFICATION-SESSION.md](VERIFICATION-SESSION.md)
  as before; `F16`–`F22` below are new Part A / Part B material and should be
  folded into the next verification report.

> **STATUS — 2026-09-07. This document is a plan, not a status, and it now
> describes a LAYOUT THAT NO LONGER EXISTS.** Read
> [../HANDOFF.md](../HANDOFF.md) first. The reasoning below is still good; the
> file and command names in it are historical.
>
> What changed:
>
> - **WP2 (F16/F17, clone identity) — OBSOLETE, and the findings are closed.**
>   WP2 specified a golden image cut before promotion plus per-clone identity
>   derivation. That whole model was removed on 2026-09-07: each VM is now built
>   from scratch on fresh Server 2025, so there is no clone and therefore no
>   shared `krbtgt` or domain SID. **F16 and F17 are closed by construction.**
>   `Initialize-RangeClone.ps1`, `Get-RangeCloneSecret.ps1` and `-Mode Image` no
>   longer exist.
> - **Control-set consolidation — IMPLEMENTED.** Every misconfiguration is
>   declared once in `modules\RangeControls.psm1`. Any WP below that assumes a
>   control must be edited in several places is describing the old layout.
> - **Three entry points — IMPLEMENTED.** `Stage-CyberRange.ps1` (structure),
>   `Setup-CyberRange.ps1` (misconfigurations), `Test-RangeConfig.ps1` (verify,
>   `-Repair` to fix drift), plus `Reset-CyberRange.ps1`. The numbered category
>   scripts, `Resume-CyberRange.ps1` and `Repair-RangeConfig.ps1` are gone, and
>   the build order is reversed: the domain is promoted healthy, then weakened.
>
> WP1, WP3, WP5 and WP11 are still unimplemented and still worth doing.

---

## 1. Decisions locked this session

These answer **Phase 0** of [IMAGE-DESIGN-PROMPTS.md](archive/IMAGE-DESIGN-PROMPTS.md).
They were open across every prior session; they are now closed. Do not re-open
them without saying so explicitly in the changelog.

| # | Question | Decision |
|---|---|---|
| D1 | Hosts per participant | **One VM per participant.** No member server, no workstation, no attacker host in the pod. |
| D2 | Isolation model | **Shared range LAN.** Participant VMs can reach each other. The LAN has no route to campus or the internet. |
| D3 | Lateral-movement targets | **Other participants' VMs.** This is what makes relay, NTLM downgrade, WinRM/RDP movement and delegation coercion exercisable despite D1. |
| D4 | Scoring baseline | **CIS Microsoft Windows Server Benchmark, pinned release.** NIST SP 800-63B is recorded as a *documented deviation* and taught as the framework conflict, not used for scoring. |
| D5 | First work package | **Finding register + `Test-RangeCompliance.ps1`** (WP1). Everything else becomes gradable once it exists. |
| D6 | Instructor infrastructure | **A range-administrator box sits on the same subnet.** It is the answer-key store, log collector, offline package source, scoring host, and red-cell C2. |
| D7 | Initial access | Provided by **range-administrator red-team implants** delivered from that box — not by a seeded artifact alone. |
| D8 | Who performs first boot | **Range administrators**, before the student ever receives the VM. This confirms WP2's personalization model is viable. |

### What D2/D3 change

The prior documents assume an isolated single host and conclude that roughly a
third of the seeded techniques are **inert**. Under D2/D3 that conclusion is wrong
in a useful way: those techniques are **not inert, they are peer-directed**. SMB
relay, `LocalAccountTokenFilterPolicy` abuse, WinRM/RDP lateral movement, coerced
authentication and BloodHound session edges all become live — the second host is
another student's box.

Gap **G1** is therefore not "cut the technique or add a host". It is **"the range
is now multi-tenant, and nothing in the build was designed for that."** That is
the subject of §2 and WP2, and it is the most consequential thing in this document.

### What D6/D7/D8 change

The administrator box closes four problems that were otherwise going to be solved
with removable media and manual bookkeeping:

| Problem | Was going to be | Is now |
|---|---|---|
| Answer key must leave the VM (F18) | removable media, per VM | a store on the admin box, **pulled** during personalization |
| Nowhere for logs to go (G3) | out of scope | collection to the admin box — WP5 grows a real telemetry target |
| Offline package source (F13, WP9) | mount the ISO on every clone | a read-only share on the admin box |
| Scoring is tamperable (F22) | carry the tooling on read-only media | run it from the admin box over the (deliberately open) WinRM |

**Pull, never push.** Every one of those must be initiated *from* the admin box.
If a student VM pushes its answer key to a share, an admin credential has to exist
on a machine whose owner is a Domain Admin with no firewall — which hands over the
store containing every other participant's material. After WP2 each clone is its
own forest, so there is no trust to lean on: the admin box authenticates *to* the
student VM using that clone's derived local credential, which it can recompute
from the clone id. That is a useful synergy, and it is the reason the derivation
model in WP2 is worth the extra structure.

**D8 confirms the WP2 secret model.** Because administrators do first boot, the
master secret can be supplied as a parameter and never written to the VM. If that
ever changes — students booting their own VMs — WP2's derivation has to be
redesigned, so treat D8 as load-bearing rather than incidental.

**D7 has a scoring consequence.** A live red cell means the range now has two
independent sources of attacker artifacts: the persistence `80-persistence.ps1`
seeds at build time, and whatever the implants do during the exercise. Those must
be tellable apart or the IR exercise cannot be adjudicated — see **F24**.

Three terms are used below and should be used in the register (WP1):

- **Local** — exercisable entirely on the participant's own VM.
- **Peer** — needs a second host; under D3 that host is another participant's VM.
- **Inert** — not exercisable in this topology at all. Must be labelled a
  configuration-management finding only, and must never be graded as an exploit.

---

## 2. New findings — the cost of a shared LAN (F16–F22)

The build produces **one golden image, promoted to a Domain Controller, then
cloned**. On an isolated single host that is fine. On a shared LAN it is not.

### F16 — CRITICAL · Every clone shares `krbtgt`, the domain SID, and every NT hash

`Setup-CyberRange.ps1` promotes the host to a DC (Phase 2) and seeds the domain
(Phase 3) **before** the golden image is cut. Cloning after that copies the NTDS
database, so every participant VM has:

- the same **domain SID**,
- the same **`krbtgt` key**,
- the same NT hash for every seeded principal.

Consequences on a shared LAN:

- A **golden ticket** forged on your own VM — where the participant is already
  Domain Admin, see F18 — authenticates to **every peer VM**.
- **Pass-the-hash** with any seeded account works against every peer.
- A **DCSync** against your own box yields credentials valid across the whole range.

The exercise collapses to a single step. This is not a subtle scoring nuance; it
is the difference between a range and a trick question.

**Fix:** move the golden-image cut point to the **end of Phase 1** — machine
weakened, AD DS role staged, break-glass present, *not yet promoted* — and let
each clone promote itself into **its own forest** at first boot. Promotion mints a
unique `krbtgt` and domain SID per participant for free. Spec: **WP2**.

### F17 — HIGH · Identical domain, NetBIOS and computer name on every clone

Every clone is `range.lab` / `RANGE`, and **nothing in the repo ever renames the
computer** — `Install-ADDSForest` runs on whatever name the image carries. On one
broadcast domain that produces NetBIOS `RANGE<1C>` collisions, competing DNS
authority for `range.lab`, and tooling that cannot unambiguously name a target
(`nltest /dsgetdc:range.lab` may answer with a peer; `Rubeus` may pull tickets
from the wrong KDC while the student believes they are attacking a peer).

**Fix:** per-clone identity — computer `RANGE<nn>-DC01`, domain `r<nn>.range.lab`,
NetBIOS `R<nn>` — assigned at first boot. Spec: **WP2**.

### F18 — HIGH · The participant is Administrator, so the F3 ACL does not protect the answer key

F3 locked `C:\ProgramData\CyberRange` and `C:\CyberRange` to **SYSTEM +
Administrators**. But `20-credential-exposure.ps1` enables autologon as
`Administrator`, which on a DC is a **Domain Admin**. The participant boots
straight into the exact identity the ACL grants.

Everything in the answer key is therefore readable by the student on their own
box: every seeded password, `DC.SafeModePassword`, `BreakGlass.Password`,
`HiddenAdminPassword`, and the staged `range.config.psd1`. Combined with F16/F17,
those credentials are valid on **every peer VM**.

F3 is not wrong — it stops unprivileged and anonymous reads, which was the
reported defect — but it does not achieve what HANDOFF currently claims. **The
answer key must not remain on a participant VM.**

**Fix:** Phase 4 exports the answer key off-box and removes it from the image;
what stays behind is a build id, a register version and a hash. Spec: **WP3**.

### F19 — HIGH · `READY.txt` points the blue team at a file it must not read

`Setup-CyberRange.ps1` writes *"Blue team: the manifest above lists every change"*
and prints the manifest path — a file that is (a) ACL-restricted by F3 and (b) the
answer key. Either the blue team can read it, in which case there is no exercise,
or it cannot, in which case the instruction is false.

**Fix:** split the artifacts. A **change manifest** (what was touched, control IDs,
no secrets) may legitimately be handed over for an after-action review. An
**answer key** (credentials) never goes to a participant. Spec: **WP3**.

### F20 — MEDIUM · Placeholder credentials are enforced only by documentation

`LocalAdminAutoLogonPass = 'Password!'`, `DC.SafeModePassword = 'S@feM0de-ChangeMe!'`
and `BreakGlass.Password = 'ChangeMe-BreakGlass!2026'` still ship. HANDOFF lists
changing them as a manual pre-build blocker. Since the F1 fix,
`LocalAdminAutoLogonPass` **becomes** the Administrator password on every clone —
a documentation-only gate on a value with that blast radius is the wrong control.

**Fix:** `Assert-RangeSafety` refuses to run while any shipped placeholder is
present. Spec: **WP3**.

### F21 — MEDIUM · Break-glass failure is non-fatal, which defeats F2

`Invoke-BreakGlass` catches every exception, logs `ERROR`, and Phase 1 continues,
weakens the box, and reboots. That is precisely the condition F2 was raised to
prevent: the dangerous window opens with no recovery account. The function's own
comment says *"Never fatal to the build"* — that was the wrong call.

**Fix:** failed break-glass provisioning aborts Phase 1 unless `-Force`.
Spec: **WP3**.

### F22 — MEDIUM · Anything scored from the on-box copy is tamperable

The participant is Administrator on their own VM (F18). Any register, compliance
script, or result file stored on that VM can be edited before scoring.

**Fix:** the instructor scores from a copy carried on read-only/removable media or
run remotely, and the result is written off-box. That is a **rule** for the
operations runbook rather than a code change — but WP1 must not assume the on-box
copy is authoritative, and `Test-RangeCompliance.ps1` must be runnable from a path
other than `C:\CyberRange`. Spec: **WP1** + **WP11**.

### F23 — HIGH · The administrator box is the crown jewel on a subnet of hostile, unfirewalled hosts

Consequence of D6. The admin box holds the answer keys, the log collection, the
scoring results, the offline package share, and live C2 — and it sits one hop from
thirty machines that have **no firewall**, SMB1, null sessions, and an owner with
Domain Admin who is being actively taught lateral movement. "It is ours, so it is
fine" is not a control.

Requirements, all of which belong in the operations runbook (WP11):

- **Explicitly out of scope** in the rules of engagement, stated in the brief
  rather than assumed. Students will find it; they need to be told it is off limits
  and what happens if they touch it.
- **Hardened and firewalled** — it is the one host on the range LAN that keeps its
  firewall. Inbound: only what the collector and the share require. Outbound: WinRM
  to student VMs. Not a mirror of the student build.
- **The clone master secret does not live on it.** Derive at first boot from a value
  the administrator supplies by hand; keep the master off the range entirely — a
  password manager or an instructor laptop that never joins this subnet. If the
  admin box falls, it must not hand over every future clone as well.
- **Answer-key store is pull-only and reachable by no student credential.** See the
  "pull, never push" note above.
- **Two roles, ideally two boxes.** The C2 host is deliberately exposed to student
  traffic; the answer-key and scoring host should not be. If budget allows one VM,
  say so explicitly and accept the risk in writing.

### F24 — MEDIUM · Seeded persistence and live implants are indistinguishable, so IR cannot be adjudicated

Consequence of D7. `80-persistence.ps1` plants five mechanisms disguised as
telemetry tooling. The red cell will plant real implants. When a blue team reports
*"I found a beacon and removed it"*, nobody can currently say which one they found,
whether they got them all, or whether the thing they removed was the graded artifact.

Requirements:

- A **documented, complete list of seeded artifacts** in the answer key — the
  register (WP1) already produces this if `80-persistence.ps1` findings are recorded
  properly.
- Seeded artifacts and live implants must be **distinguishable by design** — naming
  convention, on-disk location, and beacon destination/port. Do not rely on
  timestamps alone; WP7 deliberately back-dates the seeded ones.
- The **red cell logs its own actions** against the same timeline the seeded
  narrative uses, so an instructor can reconstruct what actually happened.
- The answer key states, per artifact, whether it is **seeded history** (a prior
  compromise the student is meant to discover) or **live activity** (this round's
  intrusion). These are different exercises and are graded differently.

---

## 3. Work packages

| WP | Title | Closes | Depends on | Size |
|---|---|---|---|---|
| **WP1** | Finding register + `Test-RangeCompliance.ps1` | G4, F22 | — | L |
| **WP2** | Clone identity & first-boot personalization | G1, F16, F17 | — | L |
| **WP3** | Pre-build and hand-off safety gates | F18–F21 | — | S |
| **WP4** | Make the shipped techniques actually work | F8–F13, F15 | WP1 (to verify) | M |
| **WP5** | Advanced audit policy + restorable telemetry | G2, G3 | WP1 | M |
| **WP6** | Account lifecycle and realistic noise | G8 | WP1 | M |
| **WP7** | Incident-response narrative and timeline | G10 | WP6 | M |
| **WP8** | Sensitive data, shares and ACL depth | G5 | WP1 | S |
| **WP9** | Vulnerability-management content | G7 | WP2 (offline source) | M |
| **WP10** | GRC deliverable scaffolding | G11 | WP1 | S |
| **WP11** | Multi-tenant rules of engagement + operations runbook | F23, F24, G6 | WP2 | M |
| **WP12** | `Reset-Range.ps1` / `Get-RangeStatus.ps1` | — | WP1 | M |
| **WP13** | Privileged-access tiering — somewhere for correct remediation to land | G9 | WP6 | M |

**Dependency shape:** WP1 and WP2 are independent of each other and of everything
else; nearly everything else hangs off WP1. WP3 is small enough to ride along with
whichever of WP1/WP2 is done first.

---

## WP1 — Finding register + `Test-RangeCompliance.ps1`

**Closes:** G4 (highest GRC priority), and makes G1/G2/G5–G11 measurable.
**Why it is first:** today the range is a set of scripts that *apply* things. There
is no artifact that says what the expected state is, so remediation cannot be
scored, the Part B matrix is hand-maintained, and a silently-skipped step (F12) is
invisible. One declarative source fixes all four.

### The idea

Every intentional misconfiguration becomes a **record**, not a line of script.
The record carries what to apply, how to verify, what "fixed" looks like, which
controls it maps to, and whether it is Local/Peer/Inert. Then:

- `Test-RangeCompliance.ps1` is a **generic runner** over the register — no
  per-finding code.
- The Part B matrix in [VERIFICATION-SESSION.md](VERIFICATION-SESSION.md) and the
  technique register in the image design doc are **generated** from it.
- The build manifest carries `FindingId`, so a **build-completeness check** can
  assert that every finding expected on this host actually got applied. That catches
  the F12 class of silent failure automatically, forever.

### Files

```
config/findings/L1-identity.psd1
config/findings/L2-group-policy.psd1
config/findings/L3-registry.psd1
config/findings/L4-services.psd1
config/findings/L5-persistence.psd1
config/findings/L6-filesystem.psd1
config/findings/L7-network.psd1
config/findings/L8-pki.psd1
config/findings/L9-audit.psd1
config/findings/L10-software.psd1
modules/RangeFindings.psm1          # loader, schema validation, filtering
Test-RangeCompliance.ps1            # the runner
tools/Export-RangeDocs.ps1          # register -> markdown tables
```

### Schema — one record

```powershell
@{
    Id             = 'SMB-SRV-SIGNING-OFF'   # stable, kebab-upper, never renumbered
    Layer          = 'L3'                    # L0..L11 per archive/IMAGE-DESIGN-PROMPTS.md
    Title          = 'SMB server signing not required'
    Category       = 'smb-network'           # matches the $cat in the apply script
    Script         = 'scripts/40-smb-network.ps1'
    HostRoles      = @('dc01')               # roles this applies to

    Exercisable    = 'Peer'                  # Local | Peer | Inert
    Effective      = $true                   # $false => known no-op on Server 2025
    EffectiveNote  = ''
    RebootRequired = $false

    Controls = @{
        Nist         = @('SC-8(1)','SC-23')
        Cis          = @('3.10')
        CisBenchmark = 'Microsoft network server: Digitally sign communications (always)'
        Stig         = ''                     # fill once the STIG release is pinned
        Attack       = @('T1557.001')
    }

    # Restricted-language note: .psd1 files loaded with Import-PowerShellDataFile
    # CANNOT contain script blocks. These are strings; the loader converts them
    # with [scriptblock]::Create(). Keep them single-expression and side-effect free.
    Verify     = '(Get-SmbServerConfiguration).RequireSecuritySignature'
    Vulnerable = '$v -eq $false'
    Remediated = '$v -eq $true'

    RedObjective  = 'Relay a coerced NTLM authentication from a peer VM to this host.'
    BlueObjective = 'Detect that signing is not required and restore it.'
    Remediation   = 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force'
    Evidence      = 'Get-SmbServerConfiguration | Select RequireSecuritySignature'
}
```

**Why strings and not script blocks:** `Import-PowerShellDataFile` parses in
PowerShell *restricted language mode*, which forbids script blocks. A `.ps1`
register would allow them but stops being data — not greppable, not exportable,
not readable by a non-PowerShell consumer. Strings plus `[scriptblock]::Create()`
in the loader keeps the register data-shaped. The register is repo content under
an ACL-restricted path, so this is not an untrusted-code path; say so in a comment
so the next reviewer does not re-raise it.

### Three-state result, not pass/fail

For each finding: evaluate `Verify` to `$v`, then

| State | Condition | Meaning |
|---|---|---|
| `VULNERABLE` | `Vulnerable` is true | as-built; the blue team has not fixed it |
| `REMEDIATED` | `Remediated` is true | fixed correctly |
| `INDETERMINATE` | neither | the check surface itself changed — e.g. the service was deleted rather than reconfigured |
| `ERROR` | `Verify` threw | the check could not run |

`INDETERMINATE` is the state a two-state model gets wrong, and it will be common:
a blue team that deletes the SNMP service instead of changing the community string
has arguably done something reasonable, and an instructor must adjudicate rather
than the script silently scoring it either way. **Do not collapse it.**

### `Test-RangeCompliance.ps1`

```
Test-RangeCompliance.ps1
    [-RegisterPath <dir>]     # default: sibling config\findings; MUST be overridable (F22)
    [-Role <name>]            # default: detect (DC vs member vs standalone)
    [-FindingId <id>...]      # score a subset
    [-Format Table|Json|Csv]  # default Table to console
    [-Out <path>]             # write results; default off-box path if supplied
```

Output requirements:

- Per finding: `Id`, `State`, observed value, expected-remediated expression,
  `Exercisable`, control IDs.
- Rollup by NIST control family and by CIS safeguard: counts of
  VULNERABLE / REMEDIATED / INDETERMINATE / ERROR.
- Findings with `Effective = $false` are reported in a **separate section** and
  never counted as exploitable — only as configuration findings. This is what
  stops a student being graded on a no-op (`DisableAntiSpyware`, `LmCompatibilityLevel=0`
  for NTLMv1).
- Exit code `0` always. This is a measurement tool; a non-zero exit invites
  someone to wire it into a build gate where a vulnerable range is the *desired*
  state.

### Manifest integration

- `Write-RangeManifest` gains `-FindingId` and a `ControlIds` column.
- New `Test-RangeBuildCompleteness.ps1` (or a `-Completeness` switch on the
  compliance runner): for the detected role, assert every register finding
  produced at least one manifest row. Report anything missing as
  `NOT-APPLIED` — this is the automatic detector for F12-class silent failures.

### Migration

Do not rewrite the apply scripts in this WP. Sequence:

1. Write the register covering **what already exists** (roughly 60 findings across
   the machine and DC scripts). Derive `Controls` from the tables in
   [GRC-CONTROL-MAP.md](GRC-CONTROL-MAP.md) — the mapping work is already done.
2. Add `-FindingId` to `Write-RangeManifest` and thread it through the existing
   apply scripts. Mechanical; no behaviour change.
3. Ship `Test-RangeCompliance.ps1` and run it against a freshly built VM. Every
   finding should read `VULNERABLE`. **Anything that does not is a real defect** —
   this run is the first honest audit the build has ever had, and it is where F8–F13
   get confirmed or dismissed.
4. Generate the Part B matrix from the register and replace the hand-written one.

### Done when

- [ ] Every misconfiguration currently applied by `scripts/**` has a register record.
- [ ] `Test-RangeCompliance.ps1` runs from an arbitrary path against a built VM and
      reports all four states with a control rollup.
- [ ] `Export-RangeDocs.ps1` regenerates the Part B matrix; the hand-written one is
      deleted, not left to drift.
- [ ] Build-completeness check reports zero `NOT-APPLIED` on a clean build.
- [ ] Register records marked `Effective = $false` are excluded from exploit scoring.

---

## WP2 — Clone identity & first-boot personalization

**Closes:** G1 under D1–D3, F16, F17.
**Why:** without it, the shared-LAN topology hands every participant the keys to
every other participant's VM on first boot.

### The change in one line

**Cut the golden image before promotion, not after.** The image is a weakened,
AD-DS-staged, *unpromoted* server. Each clone promotes itself into its own forest
with its own name and its own operator secrets at first boot.

### Build model

```
OPERATOR, ONCE                             PER PARTICIPANT VM, AT FIRST BOOT
─────────────────────────────              ──────────────────────────────────
Setup-CyberRange.ps1 -Mode Image           Initialize-RangeClone.ps1 -CloneId 07 `
  Phase 1 (machine weakening,                                       -MasterSecret <s>
          AD DS role staged,                 rename computer  -> RANGE07-DC01
          break-glass account)               derive secrets   -> per-clone
  stop; write IMAGE-READY.txt                rewrite staged config
  -> snapshot, generalize, clone             reboot
                                             Phase 2 promote -> r07.range.lab / R07
                                             Phase 3 seed AD
                                             Phase 4 finalize + export answer key
```

### Per-clone identity

| Item | Value | Source |
|---|---|---|
| Computer name | `RANGE<nn>-DC01` | `-CloneId` |
| Domain DNS | `r<nn>.range.lab` | `-CloneId` |
| NetBIOS | `R<nn>` | `-CloneId` |
| Domain SID, `krbtgt` | unique | free — each clone promotes its own forest |
| `LocalAdminAutoLogonPass` | derived | HMAC-SHA256(MasterSecret, "$CloneId/adminpw") |
| `DC.SafeModePassword` | derived | HMAC-SHA256(MasterSecret, "$CloneId/dsrm") |
| `BreakGlass.Password` | derived | HMAC-SHA256(MasterSecret, "$CloneId/breakglass") |
| `HiddenAdminPassword` | derived | HMAC-SHA256(MasterSecret, "$CloneId/hiddenadmin") |

Render derived values as a password-safe string (e.g. base64 of the first 24 bytes,
plus a fixed `Aa1!` suffix so it always satisfies the *default* domain policy —
the DSRM password is set during promotion, **before** `dc/40` weakens the policy).

**Why HMAC derivation rather than random-per-clone:** the instructor recovers any
clone's secret from `CloneId` + master secret with `Get-RangeCloneSecret.ps1`, with
no per-clone bookkeeping across thirty VMs. The master secret is supplied as a
parameter at first boot and **never written to disk**; only derived values land on
the VM, and a derived value does not reveal the master.

This works because of **D8** — range administrators perform first boot before the
student receives the VM, so there is an administrator present to supply the master
secret. D8 is load-bearing for this design; if students ever boot their own VMs,
this model has to be redesigned rather than adjusted.

It also pays off later: because the admin box can recompute any clone's local
administrator credential, it can authenticate **to** each student VM for log
collection (WP5), answer-key retrieval (WP3) and scoring (F22) without any admin
credential ever being stored on a student box. Per WP2 each clone is its own
forest, so there is no domain trust to lean on and this derivation is the only
thing making pull-based operations possible. Keep the two designs together.

**Residual risk to state in the runbook:** a participant who is Administrator on
their own VM can read that VM's derived secrets, and can therefore impersonate
their own box to the admin box. They still cannot derive any peer's secret, and
they must not be able to reach the answer-key store with what they have — see F23.
That is the whole point, and it is why derivation must be per-clone-salted.

### Seeded credentials: deliberately *not* per-clone

`svc_mssql:Summer2024`, `agarcia:Welcome1` and friends are **meant** to be cracked.
Keeping them identical across clones is the right default: a student who cracks
them on their own box and reuses them against a peer has still exercised
Kerberoasting, AS-REP roasting and the escalation path — they have only skipped
rediscovery.

If rediscovery matters for scoring, add an optional
`Config.PerCloneSeedSuffix = $true` that appends a two-character clone suffix to
each seeded password (`Summer2024` → `Summer2024x7`). The password stays trivially
crackable — same wordlist plus a two-char mask — but forces per-target work.
**Ship it off by default**; the simpler behaviour is easier to adjudicate.

### Config and orchestrator changes

```powershell
Build = @{
    Mode          = 'AllInOne'   # AllInOne | Image | Clone
    StopAfterPhase = 0           # Image mode sets 1
    CloneId        = ''          # set by Initialize-RangeClone.ps1
}
```

- `Setup-CyberRange.ps1 -Mode Image` runs Phase 1, writes `IMAGE-READY.txt`
  instead of registering the resume task, and stops.
- New **Phase 1.5 (personalize)**: rename computer, rewrite staged config, reboot.
  A rename requires a reboot before promotion, so this cannot be folded into Phase 2.
- `Initialize-RangeClone.ps1` writes the derived config, re-applies
  `Protect-RangePath`, sets state to Phase 1.5 and registers the existing resume
  task. The rest of the state machine is unchanged.
- `AllInOne` keeps today's behaviour for single-VM development and testing.

### Sysprep

With the image cut pre-promotion, **generalize with sysprep before cloning** so each
clone gets a distinct machine SID and a distinct install id. Record the decision and
the sysprep answer file in the L0 provenance artifact. Note that sysprep resets the
Administrator password state — `Initialize-RangeClone.ps1` must therefore re-run
`20-credential-exposure.ps1` after personalization, which it already does at Phase 3.

### Done when

- [ ] Two clones from one image have different domain SIDs and different `krbtgt`
      hashes (`Get-ADUser krbtgt -Properties objectSid`; compare a DCSync of each).
- [ ] A golden ticket forged on clone A is **rejected** by clone B.
- [ ] `nltest /dsgetdc:r07.range.lab` from clone 07 returns clone 07's DC and
      resolution is unambiguous with peers online.
- [ ] The four operator secrets differ between clones, and
      `Get-RangeCloneSecret.ps1 -CloneId 07 -MasterSecret <s>` reproduces them exactly.
- [ ] `Setup-CyberRange.ps1 -Mode AllInOne` still builds a single VM end to end.

---

## WP3 — Pre-build and hand-off safety gates

**Closes:** F18, F19, F20, F21. Small, and it removes the remaining human-error
paths before anyone spends a hardware pass.

### Spec

1. **Placeholder gate (F20).** `Assert-RangeSafety` fails with a clear message if
   any of `LocalAdminAutoLogonPass`, `DC.SafeModePassword`, `BreakGlass.Password`,
   `HiddenAdminPassword` still equals its shipped placeholder. Keep the literal
   placeholder list in the module, not the config, so editing the config cannot
   disable the check. Add `-AllowPlaceholderCredentials` for deliberate
   off-network dry runs, and log loudly when it is used.
2. **Break-glass becomes fatal (F21).** `Invoke-BreakGlass` returns success;
   Phase 1 aborts before applying anything if it failed, unless `-Force`. The
   message must name `docs/BREAK-GLASS.md`.
3. **Split the answer key from the change manifest (F19).**
   - `manifest-<stamp>.csv` — timestamp, category, action, target, detail,
     **FindingId, ControlIds**, and **no secrets**. Safe to hand to the blue team
     for an after-action review.
   - `answerkey-<stamp>.csv` — every credential, every password, the derived
     operator secrets. Written only in this file. `Write-RangeManifest` gains a
     `-Secret` switch that routes a row here instead.
   - Audit the existing call sites: `dc/10` (`pw=<plaintext>`), `dc/50`,
     `20-credential-exposure.ps1`, `00-break-glass.ps1`.
4. **Get the answer key off the box (F18), by pull not push.** The destination is
   the administrator box (D6). Phase 4 leaves `answerkey-<stamp>.csv` and the
   staged `range.config.psd1` in place and marks the VM ready for collection; a
   `Get-RangeAnswerKey.ps1` **run on the admin box** then, per clone:
   - connects over WinRM using that clone's derived local credential,
   - retrieves both files and verifies them by hash,
   - **deletes both from the student VM** on a verified copy,
   - and records the collection in a per-cohort index.

   Do not implement this as a push from the VM to a share. A push requires a
   credential for the answer-key store to exist on a machine whose owner is a
   Domain Admin with no firewall — which would expose every other participant's
   material (F23). If no admin box is reachable, fall back to removable media and
   write a prominent warning to `READY.txt` and the log stating that the
   participant, as Administrator, can read the answer key.
5. **Rewrite `READY.txt` (F19).** Remove "Blue team: the manifest above lists every
   change." Replace with: build id, register version, image hash, break-glass
   account name, and a pointer to the operator runbook. Nothing a participant can
   use as an answer key.

### Done when

- [ ] A build with any shipped placeholder credential refuses to start.
- [ ] A build with break-glass provisioning forced to fail does not reach the
      Phase 1 reboot.
- [ ] `manifest-*.csv` contains no credential material; `grep -iE 'pw=|password' `
      over it returns nothing but column headers.
- [ ] With an export path set, no answer key remains on the VM after Phase 4.
- [ ] `READY.txt` names no file a participant should not read.

---

## WP4 — Make the shipped techniques actually work

**Closes:** F8–F13, F15. Do this *after* WP1 so each fix is verified by a register
record rather than by eye.

| Finding | Fix |
|---|---|
| **F8a** ESC1 blocked by strong cert binding | Set `HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\StrongCertificateBindingEnforcement = 1` in `dc/20`, and register it as its own graded finding — the downgrade is a blue-team catch in its own right. |
| **F8b** duplicate template OID | Mint a new OID object under `CN=OID,CN=Public Key Services,CN=Services,<config NC>` and set `msPKI-Cert-Template-OID` to it. Also copy `msPKI-Private-Key-Flag`, which is currently skipped. Confirm with `certipy find -vulnerable`. |
| **F10** RC4 never enabled domain-wide | Set `HKLM:\SYSTEM\CurrentControlSet\Services\KDC\DefaultDomainSupportedEncTypes` and the domain object's `msDS-SupportedEncryptionTypes`. Verify the issued ticket is etype 23 via `klist` after a Kerberoast. |
| **F11** LDAP signing never downgraded | Set `NTDS\Parameters\LDAPServerIntegrity = 0` and `LdapEnforceChannelBinding = 0`. This is the natural partner to the SMB signing downgrade and, under D3, is now **Peer**-exercisable. |
| **F12** `dc/10` not idempotent | Apply SPN / description / UAC flags on **both** the create and update branches of `New-RangeUser`. Then add a repo rule: *any attribute that defines a finding must be set unconditionally, never only on create.* WP1's completeness check enforces this from then on. |
| **F13** SNMP install on an isolated box | Add `Config.OfflineSourcePath` (mounted ISO `sources\sxs`), pass `-Source`, verify state after install instead of assuming, and **move the category before Windows Update is disabled**. Declare the ordering constraint in the register so it cannot silently regress. |
| **F9** NTLMv1 removed on 2025 | Keep the setting; mark the register record `Effective = $false` with a note. It stays a CIS/STIG configuration finding and stops being an exploit claim. |
| **F15b** `HKCU:` written under SYSTEM | The screensaver keys in `80-persistence.ps1` land in the SYSTEM hive on resume. Write to `HKU\.DEFAULT` plus the target profile SID, or drop the item — it is low value either way. |
| **F15a** GPO version mismatch | Update `GPT.ini` alongside `versionNumber` in `dc/40`. Cosmetic, but a blue team running `gpresult` will notice. |
| **F15d** orphaned resume task | If Phase 3 fails repeatedly, unregister `CyberRangeSetup` rather than re-running it on every boot forever. Mirror the `PromoteTries` cap already used in Phase 2. |

### Done when

- [ ] `certipy find -vulnerable` reports `RangeUserESC1` as ESC1 against a live clone.
- [ ] A Kerberoast against a clone yields an etype-23 ticket that `hashcat -m 13100`
      cracks to the seeded password.
- [ ] `dc/10` run twice produces the same SPN set as run once.
- [ ] SNMP either installs from the offline source or reports failure honestly.
- [ ] Every register record with `Effective = $false` has an `EffectiveNote`.

---

## WP5 — Advanced audit policy + restorable telemetry + collection

**Closes:** G2, and — now that D6 gives the range an administrator box — **all of
G3**, which was previously written off as unachievable.

### Collection (new scope, from D6)

- **Windows Event Forwarding will not work the usual way.** After WP2 every clone
  is its own forest, so there is no shared Kerberos realm and a source-initiated
  subscription has nothing to authenticate with. Someone will lose a day to this;
  do not let them.
- **Do this instead: the admin box pulls.** It can recompute each clone's local
  administrator credential (WP2 derivation) and WinRM is deliberately wide open, so
  a scheduled `Get-RangeLogs.ps1` on the admin box can pull `wevtutil epl` exports
  or query with `Get-WinEvent -ComputerName` per clone. Same mechanism as answer-key
  collection and scoring — write it once.
- If real WEF is wanted later, the route is source-initiated over HTTPS with
  certificate authentication, which means issuing a cert to every clone. Note it as
  an option; do not start there.
- **Be honest about what this teaches.** Collection to the admin box exists for
  *scoring and adjudication*. It is not the blue team's own centralized-logging
  exercise — students do not build or own it. If a blue-team-owned collection
  exercise is wanted, that is separate scope and should be its own work package.

### Beacon destination — a decision D6 reopens

`BeaconHost` is currently `192.0.2.1` (RFC 5737, routes nowhere), which makes the
seeded persistence a purely on-disk artifact. With a real box on the subnet there
is a better option: **point the seeded beacon at a logging sinkhole on the admin
box**. The check-ins then produce genuine network evidence — visible in `netstat`,
in the pulled logs, and with a detectable 300-second period — so the beacon can be
found by network analysis rather than only by file inspection. That is a materially
better exercise.

If you do this, give the sinkhole a **different port from the live red-cell C2**
and keep the two destinations distinct, so blue can separate seeded persistence
from the live implant (F24). Record whichever way you go in the register note; the
current config comment already anticipates this case.

### Audit policy (original scope)

- New `scripts/65-audit-policy.ps1`, applied **before** `60-logging-visibility.ps1`.
- Capture the pristine state first: `auditpol /backup /file:<answer-key path>`.
  That backup **is** the blue team's restore target and belongs with the answer key,
  not on the participant VM.
- Deliberately disable a chosen subcategory set — credential validation, logon/logoff,
  object access, privilege use, DS access — via `auditpol /set`.
- Register each subcategory as its own finding so remediation is scored per
  subcategory rather than as one lump.
- **Sysmon:** ship a known-good config in the repo. Today `60` disables the service
  if present, which makes "fix Sysmon" a task with no defined end state. Install
  Sysmon with the good config during the image build, then disable the service as
  the finding. The blue team's correct action becomes *re-enable with the supplied
  config*, which is checkable.
- **Conflict to decide and record:** `60` shrinks Security/System logs to 1 MB, which
  destroys the evidence WP7's IR narrative depends on. Raise the cap to something
  that still rolls over under load but survives a seeded timeline (suggest 20 MB),
  or move the shrink to a per-round action. Name the winner in the register note —
  this is exactly the cross-layer conflict the design prompts warn about.

**Done when:** `auditpol /get /category:*` differs from the captured baseline in
exactly the intended subcategories; each is a separate register record; a Sysmon
config exists to restore to.

---

## WP6 — Account lifecycle and realistic noise

**Closes:** G8. Also fixes a realism problem: a domain with nine users, six of them
findings, is a puzzle, not a lab.

- Seed 40–60 **ordinary** users with plausible names, departments, group memberships
  and no findings attached. Target roughly **1 finding per 8–10 accounts** so
  discovery is a skill.
- Back-date `lastLogonTimestamp`, `pwdLastSet`, `whenCreated` across a realistic
  spread. Include: dormant-but-enabled accounts, an account past any sane password
  age, a disabled-but-still-privileged account, an orphaned account whose owner
  left. Each is a register record mapping to CIS 5.3 / NIST AC-2(3).
- **Naming discipline:** planted accounts must not be greppable. If every finding
  account is described "Backup Service Account", the exercise is a string search.
  Give ordinary accounts service-shaped descriptions too.
- Note the platform constraint: `lastLogonTimestamp` is replicated and can be set
  directly; `lastLogon` is per-DC and non-replicated. On a single-DC forest, set
  both and document which tools read which.

**Done when:** an access-review exercise over the directory produces a defensible
list, and the register scores each lifecycle finding independently.

---

## WP7 — Incident-response narrative and timeline

**Closes:** G10. Depends on WP6 (the noise) and WP5 (somewhere for events to live).

Today persistence exists with no story: five mechanisms, all created in the same
second during the build, with no initial access and no root cause. There is nothing
for an IR exercise to reconstruct.

**D7 changes the shape of this work.** Initial access is now delivered live by
range-administrator implants, so the range has *two* attacker stories running at
once and this WP owns only one of them:

| | **Seeded history** (this WP) | **Live activity** (red cell, D7) |
|---|---|---|
| Created | at first boot, back-dated | during the exercise, in real time |
| Represents | a prior compromise nobody noticed | this round's intrusion |
| Graded as | *reconstruct what happened* | *detect and respond while it happens* |
| Artifacts | `80-persistence.ps1` + this WP's timeline | implants, C2 traffic, operator actions |

Keep them separable by design, not by luck (**F24**): distinct on-disk locations,
distinct naming conventions, distinct beacon destination and port, and a complete
list of the seeded set in the answer key. Do **not** rely on timestamps as the
discriminator — this WP deliberately back-dates the seeded artifacts, which is
exactly the signal an investigator would otherwise use.

The red cell should log its own actions against the same clock the seeded timeline
uses. Without that, an instructor cannot tell a missed detection from an artifact
the student never had a chance to see.

- Define the intrusion as **data**: `config/narrative/intrusion.psd1` — an ordered
  list of events with offsets from a symbolic `T0`, each naming the artifact it
  produces (a file, a registry value, an event id, a logon).
- Materialize at first boot (WP2) **relative to the clone's build date**, so a VM
  cloned three months after the image still has a coherent internal timeline.
- Chain: phished credential → RDP logon from a plausible internal address → tooling
  dropped to disk → local escalation → persistence installed → beacon starts. Each
  step leaves the artifact a student is expected to find.
- Back-date file MACE timestamps to match. Note that `$STANDARD_INFORMATION` is
  trivially settable from PowerShell while `$FILE_NAME` is not — a student with a
  forensic tool will see the discrepancy. That is a **feature** if documented as a
  timestomping lesson, and a bug if it is an accident. Decide and record it.
- Inject synthetic events under a **dedicated event source** so instructors can tell
  seeded events from real ones during adjudication.
- Write the intended reconstruction — the root cause, the sequence, the full
  persistence list — into the answer key. Without it there is nothing to grade
  against.

**Done when:** an instructor can hand a student the VM and a scenario brief, and the
answer key states the exact timeline the student is expected to reconstruct.

---

## WP8 — Sensitive data, shares and ACL depth

**Closes:** G5.

- Replace the `C:\Public\README.txt` placeholder with a synthetic dataset: an HR
  export, a finance spreadsheet, a credentials note, a backup script with an
  embedded password.
- **Every file carries a synthetic marker** — a header line and a filename
  convention — so it can never be mistaken for real data, and so it is obvious in a
  student report if it leaks. State the marker convention in the scenario brief.
- Make the **share-level vs NTFS ACL** distinction a teaching point: one share where
  the share ACL is permissive and NTFS is not, and one the other way round.
- Seed credentials in the places they really live: an unattend file, PowerShell
  history, a scheduled-task action, a script in a world-readable directory.
- Under D2/D3 the `SYSVOL$` decoy share is now reachable from peer VMs, which makes
  it worth more than it was. Register it as **Peer**.

---

## WP9 — Vulnerability-management content

**Closes:** G7. Depends on WP2's `OfflineSourcePath` — which, per D6, should point
at a **read-only share on the administrator box** holding the mounted ISO's
`sources\sxs` and the pinned third-party installers. That also resolves F13 for
every clone at once, instead of mounting an ISO on each one.

Without third-party software a credentialed scan returns configuration findings and
essentially no CVEs, so scan triage cannot be taught or graded.

- Pick two or three intentionally outdated, **offline-installable, redistributable**
  applications. Pin exact versions. Record the licence position for each — this is
  a university deployment and "we downloaded an old installer" is not a licence.
- Predict the expected scanner output (Nessus/OpenVAS) and record it in the answer
  key. If nobody has predicted it, triage cannot be graded.
- Map each to CVE / CVSS / EPSS / KEV so prioritisation is a real exercise rather
  than "patch everything".

---

## WP10 — GRC deliverable scaffolding

**Closes:** G11. Templates under `docs/templates/`, graded against the register:

- **Risk register** — one row per finding, with likelihood/impact and a rationale.
- **SSP-style control statement** — how each affected control is (not) implemented.
- **POA&M** — prioritised, resourced, dated remediation plan.
- **After-action report** — for the IR side; the artifact WP7's timeline is graded
  against.

Each template should reference finding IDs from WP1, so the student's deliverable
and the instructor's scoring run share vocabulary.

---

## WP11 — Multi-tenant rules of engagement + operations runbook

**Closes:** the operational half of D2/D3/D6/D7, F23, F24, plus G6. New
`docs/OPERATIONS.md`.

- **Rules of engagement.** Peers are live targets. State explicitly what is out of
  bounds: destroying a peer's VM, wiping disks, ransomware-style encryption,
  sustained DoS, attacking the hypervisor or the range LAN infrastructure, and
  **the administrator box** (F23). Students will find it — being told it is off
  limits, and what happens if they touch it, is the control. Without any of this,
  one participant can end another's exercise in ten seconds.
- **Administrator box build standard (F23).** It is the one host on the range LAN
  that keeps its firewall and is not built from this repo. Document: inbound rules
  (collector and share only), outbound (WinRM to student VMs), what it stores,
  what it must never store (the clone master secret), and whether the C2 role and
  the answer-key/scoring role are on the same VM. If they are, write down that the
  risk was accepted.
- **Red-cell operating rules (D7, F24).** Where implants may be dropped, what the
  live C2 destination and port are, how they differ from the seeded beacon, and
  where the red cell logs its actions so IR can be adjudicated. An unlogged red
  cell makes the IR portion ungradable no matter how good the seeded narrative is.
- **Snapshot policy.** Who takes them, when, and what the revert path is. Under D3 a
  participant can be knocked out by someone else, so per-round snapshots are an
  operational requirement, not a nicety.
- **Scoring integrity (F22).** Score from the administrator box, over WinRM, using
  the register and `Test-RangeCompliance.ps1` copies that live *there* — never the
  on-box copies, which the participant can edit. Results are written on the admin
  box, not the student VM.
- **Containment statement.** The argument for a security officer: a shared LAN of
  hosts with SMB1, no firewall, null sessions, **live C2 and red-team implants**,
  and no route to campus or the internet. Name the enforcement mechanism —
  hypervisor network isolation, a dedicated VLAN, or an air gap — and who owns it.
  D7 raises the bar here: real offensive tooling on the segment means the isolation
  claim has to be demonstrable, not asserted. Test it and record the test.
- **Backup/recovery scenario (G6).** The range seeds five `*-backup` accounts and
  exercises no backup control at all. Add a `wbadmin`/VSS state and a broken-or-absent
  backup as a finding; the restore exercise doubles as the outermost break-glass layer.
- **Lifecycle.** Build → verify → snapshot → distribute → reset → retire, and who
  owns the image at end of term.

---

## WP12 — `Reset-Range.ps1` and `Get-RangeStatus.ps1`

**Depends on:** WP1.

Once each register record carries `Remediation`, the inverse is nearly free:

- `Reset-Range.ps1 [-FindingId <id>...]` re-applies a finding, or all of them, from
  the register. Lets an instructor reset one scenario between rounds without a full
  snapshot revert.
- `Get-RangeStatus.ps1` — a fast human summary: build id, register version, phase,
  break-glass account, counts by state. The thing to run when a participant says
  "something's wrong with my box."

---

## WP13 — Privileged-access tiering

**Closes:** G9. Depends on WP6 (there must be enough accounts for a tier model to
mean anything).

The range teaches students to *find* Kerberoasting, credential theft and
over-privilege, and then gives them nowhere to put the correct fix. Without this
WP the best available answer to a Kerberoastable service account is "use a longer
password", which is not the answer.

- **gMSA support.** Ensure the KDS root key exists so a blue team can actually
  convert `svc_mssql` to a group-managed service account. Without
  `Add-KdsRootKey`, the correct remediation fails with an unhelpful error and the
  student concludes it is not possible. (The 10-hour propagation delay can be
  bypassed on a lab single-DC forest with `-EffectiveTime`; document that, because
  a student who does not know it will think the range is broken.)
- **Protected Users.** Have the group present and empty as the shipped state;
  moving the right accounts into it is a scored remediation for credential theft.
- **Authentication Policy Silos.** At minimum, present and unused, so the concept
  is discoverable.
- **A tier model in the OU structure** (WP6 builds the OUs anyway): Tier 0 / Tier 1
  / Tier 2 containers with an admin account in the wrong tier as a finding.

Each of these is a register record whose `Remediation` is the *correct* fix rather
than a workaround — which is the whole point of the layer.

---

## 4. Sequencing

**Wave 0 — before any golden image is cut.** WP3 (small; removes the placeholder and
break-glass failure modes) and the **WP2 decision** (the image cut point). Building
and distributing an image under the current model produces the F16 problem across
every clone at once, and re-cutting is the only fix.

**Wave 1 — WP1.** The register. Then run `Test-RangeCompliance.ps1` against a real
build; that run is the first honest audit and settles F8–F13 with evidence.

**Wave 2 — WP2 implementation, then WP4.** Personalization, then fix what the audit
proved broken.

**Wave 3 — content.** WP5, WP6, WP7 in that order; the IR narrative needs the noise
and the telemetry to sit in.

**Wave 4 — WP8, WP9, WP10, WP11, WP12, WP13.** Depth, GRC deliverables, operations,
and somewhere for correct remediation to land.

### Realism budget

You cannot make all eleven layers deep. Based on the stated objectives — config
management, vuln management, IR, competition tradecraft — spend the depth on
**L1 Identity**, **L9 Audit**, and **L5 Persistence**, and accept token coverage of
L8 PKI (one working ESC path, not six) and L10 Software (two applications, not a
catalogue). Record that decision so a later session does not "improve" a layer that
was deliberately shallow.

---

## 5. Open questions for the operator

Not blocking, but each one changes a work package:

1. **How many participants**, and therefore how many clones on the LAN? This sets
   whether `<nn>` is two digits and whether NetBIOS `R<nn>` collides with anything.
2. **Which CIS Benchmark release** exactly — Server 2022 (mature) or a 2025 release
   if one is final? WP1's `Controls.CisBenchmark` fields cannot be filled until this
   is pinned, and grading against a moving target loses protests.
3. **Should students be Administrator on their own box?** Autologon as Administrator
   is what makes F18 unfixable-in-place. If the intended model is that they *earn*
   privilege on their own box, autologon should target an unprivileged account and
   the exposed-credential lesson moves elsewhere. D7 sharpens this: if the red-cell
   implant is meant to *grant* the foothold, starting the student at Domain Admin
   makes the implant redundant on their own machine.
4. **Which direction does the red cell run (D7)?** Two readings, and WP7 differs:
   - *Instructor-as-red-cell:* the implant is the live intrusion, students defend.
     The seeded narrative is then prior history and must not duplicate it.
   - *Implant-as-foothold:* the implant hands students a starting position for
     attacking peers. The seeded narrative is then the whole IR exercise.
   The plan is written so both work, but the answer key wording and the grading
   split depend on it.
5. **One admin box or two (F23)?** C2 is deliberately exposed to student traffic;
   the answer-key and scoring store should not be. If they share a VM, record the
   accepted risk explicitly.
6. **Does the seeded beacon point at the admin sinkhole or stay at `192.0.2.1`?**
   See WP5. Pointing it at a logging sinkhole turns the beacon into a network-detection
   exercise; it then needs a port distinct from the live C2 (F24).
