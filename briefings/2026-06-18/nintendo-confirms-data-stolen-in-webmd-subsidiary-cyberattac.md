# [MED] Nintendo confirms data stolen in WebMD subsidiary cyberattack

**Source:** BleepingComputer
**Published:** 2026-06-18
**Article:** https://www.bleepingcomputer.com/news/security/nintendo-confirms-data-stolen-in-webmd-subsidiary-cyberattack/

## Threat Profile

Nintendo confirms data stolen in WebMD subsidiary cyberattack 
By Bill Toulas 
June 18, 2026
02:31 PM
0 
Nintendo of America has confirmed to BleepingComputer that threat actors stole survey data from the third-party TinyPulse service used internally, but its systems were not compromised.
The company’s statement comes after claims from the Shadowbyt3$ “extortion-as-a-service” threat group that they exfiltrated sensitive data related to Nintendo of America employees.
“We are aware of an issue inv…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `nintendo.com`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `nintendo.com`


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
