# Case study — "everything worked until the second reboot"

**A root-cause analysis exercise (WP18). This is a real incident from this
project, not a synthetic scenario.**

Instructors: give students *Part 1 only*, plus a box in the failed state. Do not
hand out Part 2 until they have committed to a hypothesis in writing.

---

## Part 1 — what was observed

A Windows Server 2025 build ran to completion. The host promoted itself to a
domain controller for `range.lab` and rebooted. From that point:

- **No domain account could log in.** Not the built-in Administrator, not the
  operator account, not the seeded accounts.
- The logon screen appeared normally. Credentials were rejected rather than
  hanging.
- The password was definitely correct — it had been recorded off-box and had
  worked earlier in the same build.
- The machine was otherwise healthy: it booted, services started, the directory
  was intact.
- There was **no local SAM to fall back to** — promotion removes it.

Things that had already been ruled out by earlier work on this project:
- `ForceAutoLogon` with an unverified password (fixed previously)
- `DefaultDomainName` never being set (fixed previously)
- The recovery account not existing yet (fixed previously)

## Part 1 — your task

1. Write down **three** hypotheses before touching anything.
2. For each, state what observation would **eliminate** it. This is the important
   half, and most people skip it.
3. There is one observation in Part 1 that eliminates an entire class of causes.
   Which, and what does it rule out?
4. Only then, investigate. Record what you checked and what you found.

> **The discriminating question:** why would this affect *domain* accounts but
> leave the machine otherwise working, and why only *after promotion*?
>
> Local accounts authenticate over NTLM. Domain accounts authenticate over
> Kerberos. Before promotion there were local accounts; after promotion there
> were not. So the fault is almost certainly in **Kerberos specifically**, not in
> the accounts, not in the passwords, and not in the directory. Any hypothesis
> about "the account is broken" is already eliminated — which is why the
> operator-account recovery tooling did not help, and kept not helping.

---

## Part 2 — root cause (do not distribute with Part 1)

A single registry value, written by the build:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters
    SupportedEncryptionTypes = 4
```

The intent was "allow RC4 so Kerberoasted tickets are crackable with
`hashcat -m 13100`". The mistake is that this value is an **allow-list, not an
addition**. `0x4` is RC4-HMAC *only* — it cleared AES128 (`0x8`) and AES256
(`0x10`).

RC4 is deprecated and disabled by default on Server 2025. So the KDC was
configured to offer exactly one encryption type, and that one type was refused by
the platform. No domain account could obtain a ticket. Every domain logon failed,
and there was no local SAM left to fall back on.

**Why it only appeared after promotion:** before promotion the box had local
accounts using NTLM, which never touches the KDC. The value was being written the
whole time; it simply had nothing to break yet. The orchestrator also re-ran the
script *after* promotion, so even a manual repair was overwritten on the next pass.

### The fix

```
SupportedEncryptionTypes = 0x1C   (28 = RC4 + AES128 + AES256)
```

Per-account RC4 for the Kerberoasting exercise comes from stamping
`msDS-SupportedEncryptionTypes = 4` on the individual `svc_*` accounts instead —
which is where it belonged all along. The domain-wide setting and the per-account
setting look similar and do very different things.

### Recovery from a locked-out box

From the logon screen, Win+U (or Shift five times) gives a SYSTEM shell on a box
in this state:

```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 28 /f
```

Then reboot.

---

## What this teaches

1. **The failure's *timing* is evidence.** "Only after promotion" eliminated more
   hypotheses than any log did.
2. **Allow-lists versus additions.** A bitmask that replaces rather than adds is
   one of the most common configuration mistakes there is, and it is invisible in
   a diff that only shows "value set".
3. **A correct-looking fix in the wrong place.** RC4 *was* wanted — on three
   service accounts, not on the KDC.
4. **Recovery tooling that addresses the wrong layer does not help.** The account
   was never the problem, so account-repair tooling could not fix it. When a
   recovery step "should work" and does not, question the layer, not the step.
5. **Senior people cause outages and write them up.** This one cost days. The
   write-up is worth more than the embarrassment.

## Optional second exercise — many failures, one cause

A later build produced **eight failing checks** across unrelated areas: AD users,
certificate templates, ACLs, group policy. Each looked like a separate bug.

Root cause: the `ADWS` service had start type `Disabled`. `Start-Service` cannot
start a disabled service — it throws, and `-ErrorAction SilentlyContinue` hid the
throw, so every AD-dependent step simply timed out waiting for a directory that
was never coming up.

**The lesson is the inverse of the first case.** When many unrelated things fail
at once, look for one shared dependency before debugging any of them
individually. Counting the failures is not the same as counting the causes.
