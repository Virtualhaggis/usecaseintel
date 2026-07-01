# [HIGH] Snyk Open Source adds beta C/C++ security scanning for unmanaged OSS

**Source:** Snyk
**Published:** 2021-12-08
**Article:** https://snyk.io/blog/snyk-launches-beta-support-for-cpp/

## Threat Profile

Snyk Blog In this article
Written by Daniel Berman 
December 8, 2021
0 mins read We’re happy to announce the open beta of C/C++ security scanning in Snyk Open Source , enabling development and security teams to find and fix known security vulnerabilities in their C/C++ open source code and libraries!
Used across various industry verticals and prominent within the gaming, hardware/IoT, and communications industries, C/C++ continues to have a major impact on software development and the technology…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-5481`
- **CVE:** `CVE-2020-8286`
- **CVE:** `CVE-2019-5482`
- **CVE:** `CVE-2020-8285`
- **CVE:** `CVE-2021-22898`
- **CVE:** `CVE-2021-22876`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2019-5481`, `CVE-2020-8286`, `CVE-2019-5482`, `CVE-2020-8285`, `CVE-2021-22898`, `CVE-2021-22876`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
