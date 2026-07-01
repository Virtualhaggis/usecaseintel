# [MED] New years resolution: Don’t show my security tokens when hacking my demo application on stage

**Source:** Snyk
**Published:** 2022-01-12
**Article:** https://snyk.io/blog/dont-show-security-tokens-on-stage/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
January 12, 2022
0 mins read Traditionally, we start the new year with resolutions . We want to do more good things, like working, other things we try to eliminate. Considering the latter, my 2022 resolution is tostop accidentally exposing confidential information while I hack my application during demos on stage or similar . 
Yes, this new years resolution sounds very specific, and it has an excellent security horror story behind it.
Hacking m…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `brianvermeer.nl`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `brianvermeer.nl`


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
