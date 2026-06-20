# [HIGH] Using Snyk reporting for data-driven security

**Source:** Snyk
**Published:** 2022-12-09
**Article:** https://snyk.io/blog/using-snyk-reporting-for-data-driven-security/

## Threat Profile

Snyk Blog In this article
Written by Daniel Berman 
December 9, 2022
0 mins read Editor’s note: February 6th, 2023 Get a single view of your cloud environments’ compliance with Snyk Cloud’s new Cloud Compliance Issues report.
Last month, we announced the open beta of Snyk’s new and revamped reporting. Since then, we’ve been amazed at how creative our customers have been in leveraging these new capabilities to answer all sorts of different security questions.
We’re not surprised. The new reportin…

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
