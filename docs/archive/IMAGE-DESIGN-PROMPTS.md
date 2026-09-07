# Image Design Prompts — structuring the range by OS layer

A prompt library for producing an **image design document**: what the range image
contains, organised by where in the OS the change actually lives, and on which
host it lives.

Written to close gap **G1** in [GRC-CONTROL-MAP.md](../GRC-CONTROL-MAP.md) — right
now the build is a list of scripts, and roughly a third of what it configures
cannot be exercised because there is only one host. You cannot resolve that by
editing scripts; it needs a structural decision first.

---

## How to use this

Work top to bottom. **Phase 0 first** — the topology answer changes every
subsequent layer. Then one pass per layer.

Three ways to run it:

- **Solo worksheet.** Answer in a scratch doc; the answers *become* the design doc.
- **Paste into a Claude session** one layer at a time. The session-starter prompt
  at the end sets up the context.
- **Design review.** Walk a colleague through the prompts for a layer they own.

Each layer ends with an **artifact** — the concrete thing that layer's pass should
produce. If a pass does not produce its artifact, the layer is not designed yet.

---

## The model: layers × hosts

Two axes. The current build only has the first, which is exactly why G1 exists.

|  | **DC** (`dc01`) | **Member server** (`srv01`) | **Workstation** (`ws01`) |
|---|---|---|---|
| L1 Identity & Accounts | | | |
| L2 Group Policy | | | |
| L3 Registry | | | |
| L4 Services | | | |
| L5 Tasks & Autoruns | | | |
| L6 Filesystem & Shares | | | |
| L7 Network & Boundary | | | |
| L8 Certificates & PKI | | | |
| L9 Audit & Logging | | | |
| L10 Software & Features | | | |

A worked cell, so the granularity is clear:

> **L3 Registry × srv01** — `RequireSecuritySignature=0` on LanmanServer.
> *Red objective:* relay a coerced authentication from `ws01` to `srv01`.
> *Blue objective:* detect the downgrade, restore signing, verify with
> `Get-SmbServerConfiguration`.
> *Control:* NIST SC-8(1); CIS Benchmark *Microsoft network server: Digitally sign
> communications (always)*.
> *Depends on:* L7 firewall open between `ws01` and `srv01`; L1 an account with a
> session on `ws01`.
> **Single-host verdict:** INERT — relay needs a second host.

That last line is the point of the whole exercise. Every cell gets one.

---

## Phase 0 — Scope & topology (answer before anything else)

> **ANSWERED 2026-09-03.** One VM per participant, on a **shared range LAN** with
> no campus or internet route; the lateral-movement targets are **other
> participants' VMs**. Decisions D1–D5, the consequences (findings F16–F22) and the
> resulting work packages are in [IMPROVEMENT-PLAN.md](../IMPROVEMENT-PLAN.md). The
> prompts below are kept as the record of what was asked; questions 4–5 (the
> inert-technique audit) are now WP1's `Local | Peer | Inert` tag rather than a
> one-off pass.

1. How many VMs per participant can the hardware actually carry? Get a number
   from RAM and disk, not from ambition — a DC plus one member server on 8 GB is a
   different range from a five-host pod.
2. Is the pod **per participant**, **per team**, or **shared**? This decides
   whether attacks are isolated or whether one participant's actions are visible
   to another.
3. Which of these is the range for — red practice, blue practice, or graded
   red-vs-blue? Where they conflict, which wins?
4. Go through the current technique list and mark each **exercisable** or
   **inert** in a one-host topology. (Start from the known-inert set: SMB relay,
   `LocalAccountTokenFilterPolicy`, NTLM downgrade, WinRM/RDP lateral movement,
   unconstrained-delegation coercion, RBCD, all BloodHound session edges.)
5. For each inert technique: **cut it, or add the host it needs?** A technique
   that ships configured but unusable is worse than one that is absent — it
   teaches students that the finding does not matter.
6. Is there an attacker host in the pod, or do participants bring their own Kali?
   If they bring their own, what is the network path to the range, and does that
   path itself violate the isolation claim?
7. What is the **golden image lineage**? One image cloned to all roles and
   differentiated at first boot, or separate images per role? This decides whether
   layers can assume role at build time or must detect it at runtime.

> **Artifact:** a host inventory (name, role, OS, spec, network) and a
> technique-to-host assignment table with every inert technique either reassigned
> or explicitly cut.

---

## L0 — Base image & provenance

1. Exact OS build — edition, ISO, patch level as of what date? "Server 2025" is
   not specific enough to reproduce a range a year from now.
2. What patch level should the image be frozen at, and **why that one**? Is it
   chosen so specific CVEs remain reachable, or just "whatever the ISO had"?
3. Sysprep/generalise before cloning, or clone specialised? This determines
   whether SIDs differ per participant — which matters for any scenario that
   depends on SID history or per-host uniqueness.
4. How is the image itself version-stamped so a participant's VM can be traced
   back to the build that produced it?
5. What is the snapshot policy — pre-build, post-build/pre-clone, per-round?

> **Artifact:** an image provenance record: ISO hash, build date, patch level,
> sysprep decision, version stamp, snapshot points.

---

## L1 — Identity & Accounts

The largest layer, and the one with the most cross-host dependencies.

1. Enumerate every principal the range needs, by **purpose**: attack targets,
   attack paths, persistence, decoys, legitimate-looking noise, operator
   break-glass. Which are on the DC, which are local to a member host?
2. What is the **account naming and description convention**, and does it survive
   contact with a blue team running an inventory? If every planted account says
   "Backup Service Account", the exercise is a string search.
3. How many accounts are **realistic noise** versus planted findings? A domain
   with six users and three of them Kerberoastable is not a lab, it is a puzzle.
   What ratio makes discovery a skill rather than a formality?
4. For each privileged group, who is in it and **why would a real organisation
   have done that**? A finding with no plausible backstory teaches pattern
   matching, not analysis.
5. Which accounts should be **dormant** (stale `lastLogonTimestamp`), disabled,
   or expired — and are you seeding those attributes, or will the whole directory
   look like it was created five minutes ago? (Gap G8.)
6. What does the *correct remediation* look like for each identity finding, and
   does the range make it possible? Fixing a Kerberoastable service account
   properly means a **gMSA** — does the image support that? (Gap G9.)
7. Password policy: which authority governs — CIS/STIG or NIST SP 800-63B? They
   disagree on complexity and expiry. Which does the scoring rubric use?
8. Which accounts must **never** be discoverable by participants (break-glass),
   and how is that enforced rather than hoped for?

> **Artifact:** an account register — name, host, type, groups, purpose,
> backstory, red objective, blue objective, correct remediation.

---

## L2 — Group Policy

1. Which settings belong in **GPO** versus raw registry? GPO is discoverable via
   `gpresult`/RSOP and teaches real administration; raw registry teaches hunting.
   The split should be deliberate, not incidental to how the script was written.
2. How many GPOs, and what is the link structure — domain root, OU, site? Does
   the OU structure model an organisation, or is everything at the root?
3. Which GPOs are **the misconfiguration** and which are legitimate policy the
   blue team should leave alone? Is that distinguishable from inside the VM?
4. Is there a **known-good baseline GPO** the blue team can diff against or
   restore from — or are they remediating from memory? (This is the L2 half of
   gap G4.)
5. SYSVOL artifacts beyond GPP `cpassword` — logon scripts, mapped drives,
   scheduled tasks delivered by preference? Each is a separate finding class.
6. What happens on `gpupdate /force`? Do any of your policies fight the blue
   team's remediation and silently revert it? Is that intended (a persistence
   lesson) or an accident (a scoring dispute)?

> **Artifact:** a GPO inventory — name, link target, settings, intent
> (finding/legitimate), and whether it re-asserts after remediation.

---

## L3 — Registry

1. Which registry changes exist only because there is no GPO for them, and which
   are deliberately placed outside GPO to force hunting?
2. Group the changes by **subsystem** — LSA, Winlogon, SMB, Terminal Server,
   Defender, Print, NTDS/KDC. Which subsystem does each host need?
3. Which values need a **reboot** to take effect, and which need a UEFI variable
   cleared as well (LSA PPL, VBS/Credential Guard)? Does the build verify after
   reboot, or only write and assume?
4. Which values are **silently ignored** on Server 2025 and are only there for
   parity with older material? (`DisableAntiSpyware` is the known one.) Are those
   labelled so nobody grades a student on a no-op?
5. Which 2025 defaults must be **actively downgraded** or the associated attack
   simply does not work? Current known set: LDAP signing / channel binding, KDC
   strong certificate binding enforcement, KDC supported encryption types, SMB
   signing. Which of these are you deliberately taking on?
6. Is there a machine-readable expected-state file for these values, so
   remediation can be scored? (Gap G4.)

> **Artifact:** a registry change table — path, value, host, reboot-required,
> 2025-effective (yes/no/ignored), control mapping.

---

## L4 — Services & Drivers

1. Which services are planted persistence, which are legitimately vulnerable
   configuration, and which are real services that merely need to be running?
2. Are there **unquoted service paths** or weak service-binary/registry ACLs?
   That is a classic privilege-escalation class the range does not currently
   cover at all.
3. Which services must survive a reboot and which should be re-created if killed?
   Does the blue team removing one actually stay removed?
4. Which services exist on which host? A service account with an SPN and no
   service behind it is a BloodHound edge with no exploit — is that acceptable?
5. What does the service inventory look like to a blue team doing CIS Control 4.8
   (disable unnecessary services)? Can they tell planted from legitimate?

> **Artifact:** a service register — name, host, purpose, start type, account,
> binary path, ACL posture, red/blue objective.

---

## L5 — Scheduled Tasks & Autoruns

1. Enumerate every autorun mechanism in use: scheduled tasks, Run/RunOnce, startup
   folder, Winlogon Shell/Userinit, services, WMI event subscriptions, COM
   hijacks. Which are you using, and which deliberately not?
2. How **redundant** is persistence meant to be? If the blue team kills one and
   the beacon returns, that is a lesson — but only if they can eventually win.
   What is the intended number of mechanisms, and is there a documented complete
   list so an instructor can adjudicate?
3. What identity does each task run as, and is that identity itself a finding?
4. Do any tasks re-create the others? Is there a persistence *graph*, or five
   independent items?
5. What is the **discovery difficulty** of each — trivially visible in Autoruns,
   or genuinely hidden? Is there a deliberate spread from easy to hard?
6. Do the artifacts have coherent **timestamps** that support an IR timeline, or
   were they all created during the build at the same second? (Gap G10.)

> **Artifact:** a persistence map — mechanism, host, identity, trigger,
> difficulty tier, timestamp story, and what "fully removed" means.

---

## L6 — Filesystem, Shares & ACLs

1. Which shares exist on which host, with what share-level and NTFS ACLs? Is the
   difference between share and NTFS permissions itself a teaching point?
2. What **data** is planted, and does any of it matter? Right now the over-shared
   folder holds a README. Synthetic PII/CUI would give data classification, ACL
   remediation, and IR blast-radius scoping something to bite on. (Gap G5.)
3. If you plant synthetic sensitive data: how is it clearly marked as synthetic,
   so it can never be mistaken for real, and so it cannot leak into a report as
   though it were?
4. Which file ACLs are findings (hive ACLs, service binary paths, script
   directories) versus incidental?
5. Where do credentials sit on disk — scripts, config files, unattend files,
   PowerShell history, browser stores? Which of these are you seeding?
6. Where does the **answer key** live, and is it locked away from participants?
   (Already fixed: `C:\ProgramData\CyberRange` and `C:\CyberRange` are
   ACL-restricted. Any new artifact directory needs the same treatment.)

> **Artifact:** a share and data map — path, host, ACLs, contents,
> synthetic-data marking, red/blue objective.

---

## L7 — Network & Boundary

1. What is the pod's network topology, and what enforces isolation from the
   production network — hypervisor configuration, a VLAN, an air gap? The build
   disables the Windows firewall on all profiles, so host-level containment is
   gone by design.
2. Which services are reachable from which host? Draw it. This is where inert
   techniques become visible: no path means no attack.
3. Is there any egress at all? If yes, what stops a clone from reaching the
   internet with SMB1, null sessions and no firewall? If no, how do
   Features-on-Demand and any post-build tooling get installed? (This tension is
   already biting — SNMP install needs Windows Update, which the build disables.)
4. Should the firewall be **off entirely**, or **on with deliberately bad rules**?
   Off is a single finding; bad rules are a rule-review exercise and much closer
   to real assessment work.
5. What is the DNS design? Does the DC serve DNS for the pod, and does any
   scenario depend on DNS (ADIDNS, LLMNR/NBT-NS poisoning)?
6. Where does the beacon point, and can that value reach anything real? (Now
   `192.0.2.1` — RFC 5737 documentation space, routes nowhere.)

> **Artifact:** a network diagram plus a reachability matrix (source host →
> destination host → port → open/closed → which technique depends on it).

---

## L8 — Certificates & PKI

1. Is AD CS in scope, and on which host — the DC, or a separate CA server?
   Co-locating the CA on the DC is unrealistic and changes the attack surface.
2. Which ESC path(s) are being taught? ESC1 is currently attempted; ESC2/3/4/6/8
   are distinct misconfigurations with distinct remediations.
3. Does the platform **allow** the attack to complete? Since the Feb-2025
   milestone of KB5014754, PKINIT with a caller-supplied SAN and no SID extension
   is rejected under Full Enforcement — so ESC1 needs
   `StrongCertificateBindingEnforcement` deliberately lowered. Is that downgrade
   itself a finding the blue team should catch?
4. Is each template's `msPKI-Cert-Template-OID` unique? Cloning a built-in
   template without minting a new OID breaks template resolution at the CA.
5. What is the correct remediation for each ESC finding, and can the blue team
   perform it — do they have the CA console and the rights?
6. Is certificate-based persistence in scope (a stolen cert outliving a password
   reset)? That is one of the strongest lessons AD CS offers.

> **Artifact:** a PKI design — CA placement, template inventory with OIDs and
> ACLs, enforcement-setting decisions, and a validation command per finding
> (`certipy find -vulnerable`).

---

## L9 — Audit, Logging & Telemetry

The thinnest layer today, and the one the blue team lives in. (Gaps G2, G3.)

1. What is the **advanced audit policy** state per host? Not log sizes — the
   `auditpol` subcategories. Which are deliberately off, and does the blue team
   have a baseline to restore? Capture pre/post with `auditpol /backup`.
2. Which logs are shrunk or cleared, and does any scenario depend on evidence
   that shrinking would destroy? Retention and the IR exercise fight each other.
3. Is Sysmon deployed? If it is disabled as a finding, is there a **config to
   restore**, or does "fix Sysmon" have no defined end state?
4. Where do logs go? Is there a collector, WEF, or SIEM — or is every
   investigation local `Event Viewer` work? (Gap G3.)
5. What detections *should* fire if the blue team does everything right? If the
   answer is "we do not know", the blue side is not designed, only the red side.
6. Is PowerShell logging off as a finding, and does that conflict with wanting an
   IR trail? Which wins?
7. What does the blue team's evidence look like at the end — is there a defined
   set of artifacts an instructor can check a report against?

> **Artifact:** a telemetry plan — audit policy per host (intended vs baseline),
> log retention, Sysmon posture, collection design, and an expected-detections
> list.

---

## L10 — Software & Features

1. Which Windows features and Features-on-Demand are required, and **where does
   the payload come from** on an isolated box? FoD defaults to Windows Update,
   which the build disables. Mount the ISO `sources\sxs` and pass `-Source`.
2. Is any genuinely vulnerable third-party software installed? Without it a
   credentialed vulnerability scan returns configuration findings and essentially
   no CVEs, which makes the vulnerability-management objective thin. (Gap G7.)
3. If yes: how is it installed offline, is redistribution licensed, and is it
   pinned to a specific version so the range is reproducible?
4. What tooling do participants get on the box versus bring themselves?
5. Which features are **findings** (SMB1, PSv2 engine, TFTP) versus
   **infrastructure** (AD DS, DNS, AD CS)? Can a blue team tell them apart?
6. What is the intended output of a Nessus/OpenVAS scan against the finished
   image? If nobody has predicted it, scan triage cannot be graded.

> **Artifact:** a software bill of materials — feature/app, host, version, install
> source, offline method, finding-or-infrastructure, expected scanner output.

---

## L11 — Operator & safety plane

Not part of the exercise; the reason the exercise can be run twice.

1. What is the break-glass path per host, and is it **tested** before each build?
   (`scripts\00-break-glass.ps1`; runbook in [BREAK-GLASS.md](../BREAK-GLASS.md).)
2. Where does the answer key live, who can read it, and is that enforced by ACL?
3. What is the reset story between rounds — snapshot revert, or a
   manifest-driven `Reset-Range.ps1`? If snapshots, whose job is taking them?
4. How does an instructor **verify** a participant VM is in the expected starting
   state? This is gap G4 again, from the operations side.
5. What is the containment argument you would give a security officer who asks
   why a machine with SMB1, no firewall and null sessions is on the campus estate?
6. Who owns the image, and what happens at end of term?

> **Artifact:** an operations runbook — build, verify, snapshot, distribute,
> reset, retire — plus the containment statement.

---

## Cross-cutting prompts

Run these once the layers are drafted. They catch the failures that live between
layers, which is where this project has actually been bitten.

1. **Ordering.** What is the correct apply order, and which layers break if run
   out of sequence? Known example: L10 needs Windows Update *before* L3 disables
   it. Draw the dependency graph.
2. **Reboot boundaries.** Which layers only take effect after a reboot, and does
   the phase structure respect that? Which need a *second* reboot (VBS, UEFI-locked
   settings)?
3. **Idempotency.** If a layer is re-applied, does it converge or drift? Known
   failure: `dc/10` applies SPNs only on the create branch, so a retry produces
   zero Kerberoast targets.
4. **Role detection.** For layers that behave differently on a DC, is the
   behaviour selected at build time or detected at runtime? What happens to a
   local-SAM change when the host is later promoted?
5. **Conflicts.** Which layers fight each other? (L9 wants evidence; L3 shrinks
   logs. L7 wants isolation; L10 wants a package source.) Name each conflict and
   decide the winner explicitly.
6. **Blue-team reversibility.** For every finding, can it actually be fixed from
   inside the VM with the rights participants have? A finding that cannot be
   remediated is a trick question.
7. **Scoring.** For every finding: what is the check that proves it is fixed?
   That set of checks *is* `Test-RangeCompliance.ps1` (gap G4).
8. **Realism budget.** Which layers get realistic depth and which get a token
   entry? You cannot make all ten deep. Decide where the course actually spends
   its teaching time.

---

## Session-starter prompt

Paste this to open a design session, then work one layer at a time:

```
I'm designing an intentionally vulnerable Windows Server 2025 range image for a
university red-vs-blue course (config management, vuln management, IR, collegiate
competition tradecraft). I want to structure the image by OS layer rather than by
build script.

Context:
- Repo: Setup-CyberRange.ps1 orchestrator, config/range.config.psd1,
  scripts/10-90 (machine-level), scripts/dc/00-50 (AD).
- Layer taxonomy and per-layer prompts: docs/IMAGE-DESIGN-PROMPTS.md
- Decisions, new findings and work packages: docs/IMPROVEMENT-PLAN.md
- Control mappings and known gaps: docs/GRC-CONTROL-MAP.md
- Open verification findings: docs/VERIFICATION-REPORT-2026-09-03.md
- Topology (DECIDED): ONE VM per participant, all on a shared range LAN with no
  campus/internet route. Lateral-movement targets are other participants' VMs, so
  peer-directed techniques are exercisable. The range is therefore multi-tenant.

For layer <Lx — name>, work through its prompts with me. For each item you
propose, give me: host, red objective, blue objective, control mapping, what it
depends on in other layers, and whether it is exercisable in the topology we
settle on. Challenge anything that is configured but not exploitable — I would
rather cut a technique than ship one that teaches students the finding does not
matter.
```

---

## Output: the image design document

The passes above should collect into a single document with this shape:

1. **Scope & topology** — hosts, roles, network, what is explicitly out of scope.
2. **The layers × hosts matrix** — one row per layer, one cell per host.
3. **Per-layer detail** — the eleven artifacts listed above.
4. **Technique register** — every technique, its host, its control mapping, its
   red and blue objectives, its verification command, and whether it is
   exercisable. This is the master list; the Part B matrix in
   [VERIFICATION-SESSION.md](../VERIFICATION-SESSION.md) should be generated from it.
5. **Build order & dependency graph** — including reboot boundaries.
6. **Operations runbook** — build, verify, distribute, reset, retire.

When the technique register exists and every row has a verification command, the
range is designed. Until then it is a collection of scripts that happen to run.
