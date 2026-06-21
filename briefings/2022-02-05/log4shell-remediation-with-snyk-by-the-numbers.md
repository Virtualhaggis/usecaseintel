# [HIGH] Log4Shell remediation with Snyk by the numbers

**Source:** Snyk
**Published:** 2022-02-05
**Article:** https://snyk.io/blog/log4shell-remediation-with-snyk-by-the-numbers/

## Threat Profile

Snyk Blog Written by Jason Lane 
February 5, 2022
0 mins read We're almost two months from the disclosure of Log4Shell , and we here at Snyk couldn't be more excited with the role we've gotten to play in finding and fixing this critical vulnerability that's impacted so many Java shops. For starters, we've been able to help our customers remediate Log4Shell 100x faster than the industry average!
How have we been able to achieve that? Well, a few ways...
Getting Log4Shell into the Snyk Intel Vulne…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-44228`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-44228`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
