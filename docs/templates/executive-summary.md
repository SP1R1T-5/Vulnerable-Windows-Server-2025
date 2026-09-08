# Executive summary — template (WP10)

**One page. No jargon. For the person who controls the budget.**

This is usually the only part a decision-maker reads, and writing it is the skill
that gets people promoted. If a sentence needs a packet capture to understand, it
does not belong here.

Rules:
- No technique names, no CVE numbers, no registry paths. Those live in the findings.
- Quantify where you can. "Twelve of nineteen accounts" beats "many accounts".
- Say what you want them to **do**, and what it costs.

---

## What we looked at
One sentence: the system, the dates, the scope. Say what was **out** of scope too.

## What we found
Three to five bullets, worst first, in business language.

> Good: "An attacker who gains any ordinary user account can become a full
> administrator of the domain in a single step, because one standard user has
> been given the ability to change any password."
>
> Bad: "DCSync rights via DS-Replication-Get-Changes-All on the domain head."

## What it means for the business
Not "an attacker could dump NTDS.dit". Rather: what stops working, what data is
exposed, what the organisation would have to tell customers or a regulator.

## What we recommend
Ranked. For each: what, roughly how much effort, and what it buys.

| # | Recommendation | Effort | Reduces |
|---|---|---|---|
| 1 | | | |

## What we are accepting for now
The short version of the risk acceptances, and when they get revisited.
