# [HIGH] Snyk makes it easier to fix Log4Shell with extended free scans

**Source:** Snyk
**Published:** 2021-12-21
**Article:** https://snyk.io/blog/snyk-fix-log4shell-extended-free-scans/

## Threat Profile

Snyk Blog In this article
Written by Simon Maple 
December 21, 2021
0 mins read Due to the recently discovered Log4Shell vulnerability , and to support the tremendous effort being mounted by the community to address it, we are happy to announce that we are increasing the free test limit in Snyk Open Source !
This means that any developer, no matter the company or project, can now use Snyk Open Source to find and fix Log4Shell with double the number of free tests, whether it’s within your IDE, yo…

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
