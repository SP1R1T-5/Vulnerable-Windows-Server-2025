# Network capture and pcap analysis (WP20)

The range is host-centric, yet the LAN carries beacon check-ins, relay attempts,
peer-to-peer lateral movement and live C2 — and none of it is currently recorded.
Interviews lean hard on TCP/IP, DNS, TLS and "read this capture and tell me what
happened", so this is a cheap way to close a real employability gap.

**This runs on the administrator box, not on student VMs.** A capture taken on the
box being investigated is both contaminated and trivially disabled by whoever owns
it.

---

## Where to capture

In preference order:

1. **Hypervisor port mirror / SPAN to the admin box.** Sees peer-to-peer traffic
   between student VMs, which is the interesting half. Hyper-V: enable port
   mirroring (`Set-VMNetworkAdapter -PortMirroring Source` on the student VMs,
   `Destination` on the collector).
2. **Capture on the admin box NIC only.** Sees beacon check-ins and anything
   aimed at the admin box. Misses student-to-student traffic entirely — say so
   when you hand out the pcap, or students will draw wrong conclusions from an
   incomplete picture.
3. **Pre-recorded pcaps.** If live capture is awkward, record one good capture per
   scenario once and ship it as a static artifact. Most of the teaching value
   survives, and it makes the exercise reproducible between cohorts.

```powershell
# Admin box, per round. pktmon ships in-box; tshark if you have it.
pktmon start --capture --pkt-size 0 --file-name round3.etl
pktmon stop
pktmon etl2pcap round3.etl --out round3.pcap
```

Publish per-round pcaps as evidence alongside the answer key, hashed per
`EVIDENCE-HANDLING.md`.

## Exercises that fall straight out of what the range already does

Every one of these maps to a control that is already in the table — no new build
work is required to make them real.

| Exercise | What it exploits | Control |
|---|---|---|
| **Find the beacon by its period.** Identify a host phoning out every 300s to a fixed port. | `persist.beacon*` | T1095 |
| **Spot SMB1 in use.** Dialect negotiation is visible in the clear. | `smb.srv.smb1`, `smb.live.smb1` | T1210 |
| **Spot unsigned SMB** and explain why that enables relay. | `smb.srv.require` | T1557.001 |
| **Recover credentials from the wire.** WinRM with `AllowUnencrypted`, SNMP community `public`, LDAP simple bind. | `winrm.svc.unencrypted`, `snmp.community` | — |
| **Watch a relay attempt** between two student VMs and reconstruct who coerced whom. | `smb.srv.require` + shared LAN | T1557.001 |
| **Correlate host and network.** Take one event, find it in both the Sysmon log and the pcap. | — | — |

That last one is the point of pairing this with WP19: the same event seen two
ways, and the lesson that one telemetry source is never enough. A student who
can say "the host log says the process started, the pcap says where it went, and
neither alone is sufficient" has understood something most juniors have not.

## What to teach alongside it

- **Read the three-way handshake and what a RST means.** Most beacon traffic in
  this range is a *failed* connect, because the seeded beacon points at a target
  that may not answer. A failed connection attempt is still evidence, and
  recognising that is the skill.
- **DNS before HTTP.** The name lookup usually tells you more than the payload,
  and it survives encryption.
- **Encryption is not opacity.** Destination, timing, volume and JA3/JA4 remain
  visible. Students who think TLS ends the investigation should learn otherwise
  here.

## Note on the seeded beacon

If `BeaconHost` still points at `192.0.2.1` (RFC 5737, routes nowhere), the
beacon produces connection *attempts* and nothing else — which is a legitimate
exercise, just a thinner one. Pointing it at a logging sinkhole on the admin box
gives a full conversation to analyse. That decision is open; see WP5 and the open
questions in `HANDOFF.md`. If you do point it at the sinkhole, use a **port
distinct from the live red-cell C2** so the seeded artifact stays separable from
real implant traffic (F24).
