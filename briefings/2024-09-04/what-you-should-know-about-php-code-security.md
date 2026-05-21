# [HIGH] What you should know about PHP code security

**Source:** Snyk
**Published:** 2024-09-04
**Article:** https://snyk.io/blog/php-code-security/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
September 4, 2024
0 mins read When it comes to web development, PHP is a widely used scripting language. With its popularity, it is crucial to understand the potential security risks associated with PHP and the measures to mitigate them. Whether you deploy CMS applications using WordPress or build enterprise applications with the Laravel PHP framework, the importance of PHP security and the business impact of some notable PHP interpreter vulnerabil…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-0568`
- **CVE:** `CVE-2023-3823`
- **CVE:** `CVE-2023-0662`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-0568`, `CVE-2023-3823`, `CVE-2023-0662`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
