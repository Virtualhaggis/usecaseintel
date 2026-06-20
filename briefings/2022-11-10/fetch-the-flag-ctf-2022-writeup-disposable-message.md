# [MED] Fetch the Flag CTF 2022 writeup: Disposable Message

**Source:** Snyk
**Published:** 2022-11-10
**Article:** https://snyk.io/blog/fetch-the-flag-ctf-2022-writeup-disposable-message/

## Threat Profile

Snyk Blog In this article
Written by Michael Aquilina 
November 10, 2022
0 mins read Thanks for playing Fetch with us! Congrats to the thousands of players who joined us for Fetch the Flag CTF . And a huge thanks to the Snykers that built, tested, and wrote up the challenges !
In this blog post, we’ll be talking about the Disposable Message challenge within Snyk’s 2022 Fetch the Flag CTF event. This challenge involved using CSS injection techniques to exploit a vulnerable web page and retrieve t…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `disposable-message.c.ctf-snyk.io`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `disposable-message.c.ctf-snyk.io`


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
