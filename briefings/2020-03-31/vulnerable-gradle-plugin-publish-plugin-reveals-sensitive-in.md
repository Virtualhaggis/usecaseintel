# [HIGH] Vulnerable Gradle plugin-publish plugin reveals sensitive information

**Source:** Snyk
**Published:** 2020-03-31
**Article:** https://snyk.io/blog/vulnerable-gradle-plugin/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
March 31, 2020
0 mins read Just a few days ago, on March 27, a security vulnerability was disclosed and published — CVE-2020-7599 — on Gradle's plugin-publish plugin. It affects all versions of the package below 0.11.0. The vulnerability was found on March 4 by Danny Thomas, Developer Productivity at Netflix, and reported to Gradle straight away.
Sensitive information The issue found in this package is a so-called “Insertion of Sensitive Inform…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-7599`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-7599`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
