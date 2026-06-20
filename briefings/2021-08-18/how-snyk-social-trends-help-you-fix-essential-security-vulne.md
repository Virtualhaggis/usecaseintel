# [HIGH] How Snyk Social Trends help you fix essential security vulnerabilities

**Source:** Snyk
**Published:** 2021-08-18
**Article:** https://snyk.io/blog/snyk-social-trends-fix-security-vulnerabilities/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
August 18, 2021
0 mins read Recently, Snyk added Social Trends to its vulnerability data . This new indicator shows you what vulnerabilities are trending so you can better prioritize remediation. Our research team found out that there is a strong correlation between socially trending vulnerabilities and the existence of exploits that can actually harm your application.
Following the social trends of security vulnerabilities makes practical sens…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-9484`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-9484`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
