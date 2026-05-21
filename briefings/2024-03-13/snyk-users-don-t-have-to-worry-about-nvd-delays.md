# [HIGH] Snyk users don't have to worry about NVD delays

**Source:** Snyk
**Published:** 2024-03-13
**Article:** https://snyk.io/blog/snyk-users-dont-have-to-worry-about-nvd-delays/

## Threat Profile

Snyk Blog In this article
Written by Hadas Bloom 
Tal Dromi 
March 13, 2024
0 mins read Editor's note: September 19, 2024 Update: NVD still has significant delays.
355 CVEs published in the Snyk Security Database in 2024 have yet to be analyzed by NVD.
You may have encountered recent discussions and the official notice from NVD (National Vulnerability Database) regarding delays in their analysis process. This message was posted on the February 13:
We want to assure you that these delays do not c…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-22243`
- **CVE:** `CVE-2024-1597`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-22243`, `CVE-2024-1597`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
