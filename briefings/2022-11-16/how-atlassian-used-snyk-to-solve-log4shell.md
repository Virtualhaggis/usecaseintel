# [HIGH] How Atlassian used Snyk to solve Log4Shell

**Source:** Snyk
**Published:** 2022-11-16
**Article:** https://snyk.io/blog/how-atlassian-used-snyk-to-solve-log4shell/

## Threat Profile

Snyk Blog In this article
Written by Sarah Conway 
November 16, 2022
0 mins read Snyk recently launched a multi-day live hack series with AWS, where experts demonstrated exploits in real-time and explained how to defend against those vulnerabilities. This series helped viewers discover new ways to improve security across the application stack for AWS workloads.
As part of the series, Micah Silverman (Director of Developer Relations, Snyk) and Chris Walz (Senior Security Engineer, Atlassian) disc…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-44228`
- **CVE:** `CVE-2021-45046`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-44228`, `CVE-2021-45046`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
