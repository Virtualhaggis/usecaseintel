# [HIGH] Snyk in 30: Open source security for Atlassian Bitbucket Cloud

**Source:** Snyk
**Published:** 2022-12-15
**Article:** https://snyk.io/blog/snyk-open-source-security-atlassian-bitbucket/

## Threat Profile

Snyk Blog In this article
Written by Marco Morales 
December 15, 2022
0 mins read In our latest Snyk in 30 , Jason Lane (Director of Product Marketing) and I (Marco Morales, Partner Solutions Architect) showcased Snyk Open Source with a focus on our integration with Bitbucket Cloud .
They covered why open source security is vital for modern app development, along with tips on taking a holistic approach to application security that goes beyond just shifting left . The session ended with a demo of…

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
