# [HIGH] Simplifying container security with Snyk’s security expertise

**Source:** Snyk
**Published:** 2022-03-08
**Article:** https://snyk.io/blog/simplifying-container-security-snyk-expertise/

## Threat Profile

Snyk Blog In this article
Written by Hadas Bloom 
March 8, 2022
0 mins read The most beautiful and inspiring aspect about open source code is, well, that it’s open source . We can look at open source packages like gifts that are exchanged between developers across the engineering world, allowing them to learn from the work other people do, contribute their own expertise, and grow their professional capabilities. Contributing to open source is much appreciated, and it is important to remember not…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-44228`
- **CVE:** `CVE-2021-3507`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-44228`, `CVE-2021-3507`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
