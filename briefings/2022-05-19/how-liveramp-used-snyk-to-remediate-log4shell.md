# [HIGH] How LiveRamp used Snyk to remediate Log4Shell

**Source:** Snyk
**Published:** 2022-05-19
**Article:** https://snyk.io/blog/liveramp-used-snyk-to-remediate-log4shell/

## Threat Profile

Snyk Blog In this article
Written by Brian Piper 
May 19, 2022
0 mins read Like any company that uses web apps or enterprise software built with Java, San Francisco-based LiveRamp was concerned that it had been infected by the Log4Shell zero-day vulnerability within Log4j — the popular open source logging library.
When Log4Shell hit in mid-December 2021, LiveRamp — a data connectivity company that integrates disparate customer data into a company’s own marketing platforms — had just completed it…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-44228`
- **CVE:** `CVE-2021-45046`
- **CVE:** `CVE-2021-45105`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-44228`, `CVE-2021-45046`, `CVE-2021-45105`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
