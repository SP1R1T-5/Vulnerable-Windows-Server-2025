# Scope decision — hybrid identity and Linux (WP22 / WP23)

> ## DECIDED 2026-09-08 — read this first
>
> **All range infrastructure lives on the single administrator VM, and there is
> no cloud resource access.**
>
> That constraint decides most of this document:
>
> | Question | Decision |
> |---|---|
> | **WP22 hybrid identity** | **Not doing it.** No cloud access rules out Options B and C. A cloud-free tabletop remains possible; the syllabus limitation is now mandatory either way. |
> | **One admin box or two (F23)?** | **One.** Risk accepted in writing below. |
> | **WP23 Linux** | **Blocked on a conflict** — see *The WP23 conflict* below. Needs one operator decision. |
>
> Everything downstream of "no internet, no cloud" is collected under
> *Operating with no external feeds*, because it affects more work packages than
> just these two.

This document existed to force a decision rather than record one; the header above
now records the decisions made. The reasoning below is kept because a future
session will otherwise re-litigate it.

Both are genuine employability gaps and neither is cheap. The failure mode they
share is drift: staying permanently "planned" while cohort after cohort graduates
without them, and discovers the gap in an interview instead. **Commit to a
version, or write it into the syllabus as a known limitation.** Both are
respectable. Silence is not — which is why WP22 now carries a syllabus sentence
rather than nothing.

---

## WP22 — Hybrid identity

### The problem

On-premises-only Active Directory is a 2015 curriculum. Most enterprises are
hybrid, and the incidents that actually happen now are in cloud identity: token
theft, OAuth consent phishing, conditional-access gaps, over-permissioned service
principals, and refresh tokens that outlive a password reset.

A student who can Kerberoast but has never seen Entra ID is not employable in the
way this course intends. That is a strong claim and it is the reason this document
exists.

### Options

| Option | Cost | What it buys | What it does not |
|---|---|---|---|
| **A. Nothing.** Document the limitation. | Zero | Honesty; students can seek it elsewhere | Everything |
| **B. Tabletop + read-only walkthrough** of a developer-tier tenant | ~1 session to prepare | Vocabulary, the shape of the attack surface, interview competence | Hands-on, no range integration |
| **C. Entra Connect sync** from `range.lab` to a test tenant | Days, plus a tenant and ongoing ownership | Password-hash-sync and hybrid-account attack paths become real | Significant; also puts a real cloud tenant adjacent to a deliberately vulnerable forest |

### Decision: Option A, with a cloud-free tabletop if time allows

**No cloud resource access rules out B and C.** Option B needed a developer-tier
tenant to walk through; Option C needed a tenant to sync into. Neither is
available, and Option C was already the wrong idea — syncing a deliberately
broken forest (no firewall, SMB1, exposed credentials, students with Domain
Admin) into a real tenant is an exposure, not a lab configuration.

What remains possible with no cloud at all:

- **A pure tabletop.** Slides and a whiteboard: token theft, OAuth consent
  phishing, conditional-access gaps, over-permissioned service principals. No
  tenant required. This gets students the vocabulary and the shape of the attack
  surface, which is most of what an interview tests, and none of the hands-on.

**The syllabus limitation is now mandatory, not optional.** Write it in plainly:

> This course covers on-premises Active Directory. It does not cover Entra ID,
> hybrid identity, or cloud IAM. Most enterprises are hybrid, and a substantial
> share of current identity incidents occur in cloud identity systems. Students
> intending to work in identity or cloud security should treat this as a known
> gap and seek it elsewhere.

That sentence is the whole deliverable for WP22. It costs nothing, it is honest,
and it is considerably better than a student discovering the gap in an interview.

## WP23 — A Linux host

### The problem

Every security team runs Linux tooling and most estates are mixed. One host turns
this from a Windows course into a security course.

### The WP23 conflict (needs one operator decision)

The original argument for WP23 was that the Linux host earns its keep twice: it
hosts the WP5 collector, the Sigma tooling and Zeek/tshark, *and* doubles as a
second operating system for students to hunt on. **The single-admin-VM decision
breaks that argument**, and it cannot be repaired by putting the teaching content
on the admin box:

> The administrator VM holds every answer key, the scoring results, the log
> collection and the live C2. **F23 requires it to be explicitly out of scope and
> firewalled.** A host that students are invited to hunt on cannot also be the
> host they are forbidden to touch. Those two requirements are not reconcilable,
> and trying to split the difference gets the worst of both.

So there are two coherent positions, and this needs a call:

| Option | What it means | Cost |
|---|---|---|
| **A. No Linux.** | Document it as a syllabus limitation alongside WP22. The range stays a Windows course. | Zero |
| **B. One Linux VM as a pure teaching target.** | *Not* infrastructure — it runs no collector, holds no keys, stores nothing. Just a second OS to hunt on, in scope, disposable. | One more VM per pod or one shared |

**Recommendation: B, if a VM can be found.** It is compatible with "all
infrastructure on the admin box" because a teaching target is not infrastructure.
It keeps F23 intact — the admin box stays out of scope and unhunted. And it is
the cheapest way to stop this being a Windows-only course.

**If B is not affordable, take A and say so in the syllabus.** What must not
happen is the third option nobody chooses deliberately: putting student-facing
content on the admin box because it is the only Linux available.

### Minimum viable content (Option B only)

One VM, shared or per pod, seeded so that a second operating system's worth of
hunting and hardening is available:

- SSH exposed, password authentication permitted
- A weak `sudo` rule (`NOPASSWD` on something reachable)
- A world-readable secret — credentials in a script, a `.env`, or a stray backup
- Cron-based persistence, as the counterpart to the Windows scheduled task
- A world-writable directory on `$PATH`

Each should be expressible the same way the Windows controls are — intended
value, check, revert — if a Linux control table is ever built. **Do not start
there.** Seed it by hand first and see whether the content earns a table.

### Housekeeping

Check the licence and support position for the chosen distribution. A university
deployment wants a clear redistribution story, and "we grabbed an ISO" is not one.

---

## Operating with no external feeds

"No cloud resource access", combined with the existing no-internet requirement,
reaches further than WP22. Several work packages assume a live feed that will not
exist. Each needs a **frozen, dated local copy staged on the admin box**, and each
copy needs an owner who refreshes it between cohorts.

| What assumes a feed | Used by | Offline substitute |
|---|---|---|
| **EPSS scores, CISA KEV catalogue** | WP9, WP14 prioritisation | Snapshot both to CSV, date-stamp them, stage on the admin box. Tell students the date — prioritising on stale data *and knowing it* is realistic; not knowing is not. |
| **CVE / NVD lookups** | WP9 scan triage | Export the relevant CVE records for the pinned software versions at build time |
| **Sysmon binary** | WP19 | Not shipped with Windows. Stage `sysmon64.exe` on the admin share |
| **Sigma rule repository + `sigmac`/`sigma-cli`** | WP19 | Stage a dated snapshot of the rule repo and the converter |
| **Zeek / tshark / Wireshark** | WP20 | Stage installers on the admin share |
| **ATT&CK Navigator, attack.mitre.org** | WP15 coverage discussion | Stage the Navigator offline build and the ATT&CK JSON bundle |
| **Windows Features-on-Demand payloads** | SNMP, existing finding F13 | Mount the ISO `sources\sxs` and pass `-Source`; this was already required |
| **Third-party vulnerable software** | WP9 / G7 | Offline installers, pinned versions, licence position recorded |

**Teaching point worth keeping, not hiding:** an air-gapped estate is a real
environment, and "our vulnerability data is 90 days old" is a real finding in a
real assessment. Date-stamp the snapshots and let students discover the staleness
and write it up. That is more valuable than pretending the feeds are live.

---

## Decision record

| WP / question | Decision | Decided by | Date | Notes |
|---|---|---|---|---|
| **WP22 hybrid identity** | **Not doing it** (Option A). Cloud-free tabletop optional. | Operator | 2026-09-08 | No cloud resource access. Syllabus limitation is mandatory — wording above. |
| **One admin box or two (F23)** | **One.** All infrastructure on the single admin VM. | Operator | 2026-09-08 | Risk accepted below. Mitigations become mandatory. |
| **WP23 Linux** | **Pending** — Option A or B | | | Recommendation: B, a pure teaching target, if a VM can be found. Do **not** put student-facing content on the admin box. |

---

## Risk acceptance RA-2026-001 — single administrator VM

Recorded here because the decision above created it. This doubles as a worked
example of [the risk-acceptance template](templates/risk-acceptance.md).

**Finding:** F23 — the administrator box is the crown jewel on a subnet of
hostile, unfirewalled hosts.
**Accepted by:** _range owner — sign here_ **Date:** 2026-09-08
**Review date:** end of first cohort

### What we are not fixing, and why

F23 recommended splitting the C2 role (deliberately exposed to student traffic)
from the answer-key, scoring and log-collection roles (which must not be). All of
it will run on one VM instead. The reason is resource availability, which is a
legitimate reason and should be recorded as the actual one.

### What this concentrates

One host now holds: every answer key, the scoring results, the log collection,
the offline package share, and live C2 — one hop from ~30 machines with no
firewall, SMB1 and null sessions, whose owners hold Domain Admin on their own box
and are being actively taught lateral movement. A compromise of this VM is a total
compromise of the exercise: answers, scores and the means to attack every
participant.

### Compensating controls — mandatory, not optional

Because the split is not happening, these stop being recommendations:

1. **Firewalled.** The one host on the range LAN that keeps its firewall on.
   Inbound: only what collection and the share require. Outbound: WinRM to student
   VMs. It is **not** built from this repo.
2. **Explicitly out of scope** in the rules of engagement, stated in the student
   brief. Students will find it; being told it is off limits, and what happens if
   they touch it, is the control.
3. **The clone/build master secret does not live on it.** Off the range entirely —
   a password manager or an instructor laptop that never joins this subnet.
4. **Pull, never push.** Collection is initiated from the admin box using each
   clone's derived credential, so no admin credential ever lands on a student VM.
   Verification check A15 exists for exactly this.
5. **Answer keys encrypted at rest** on the share, given that the C2 role shares
   the host.
6. **Snapshot before each round**, so a compromise is recoverable without
   reconstructing the cohort's scoring by hand.

### Residual risk

An attacker who compromises the C2 service reaches the answer keys and scoring on
the same host. The compensating controls reduce likelihood; they do not reduce
impact, because the impact is structural. Accept it knowingly, or find a second
VM.

### Trigger for revisiting

A second VM becoming available; any student reaching the admin box; a second
cohort running concurrently with the first.
