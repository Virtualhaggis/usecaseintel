# [HIGH] Improving developer experience with security tools at Pinterest

**Source:** Snyk
**Published:** 2022-07-14
**Article:** https://snyk.io/blog/improving-developer-experience-with-security-tools-at-pinterest/

## Threat Profile

Snyk Blog In this article
Written by Megan Moore 
July 14, 2022
0 mins read Using open source libraries securely is an ongoing priority at large organizations. One big challenge is integrating security tools into the developer workflow — and setting up a system that prioritizes vulnerability fixes — without overwhelming developers. But what does a successful approach look like?
Our very own Simon Maple (Field CTO, Snyk) talked with Kalpesh Dharwadkar (Product Security Engineer, Pinterest) to lea…

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
