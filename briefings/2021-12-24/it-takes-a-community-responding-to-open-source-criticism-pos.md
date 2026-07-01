# [HIGH] It takes a community: Responding to open source criticism post-Log4Shell

**Source:** Snyk
**Published:** 2021-12-24
**Article:** https://snyk.io/blog/responding-to-open-source-criticism-post-log4shell/

## Threat Profile

Snyk Blog In this article
Written by Randall Degges 
December 24, 2021
0 mins read The last week has been a wild ridefor just about everyone in the technology world due to the public disclosure of the Log4Shell vulnerability . As a developer security company, Snyk has built our business around proactive automation to identify and fix security issues in applications. To say we’ve been busy this week would be an understatement.
With that being said, however, one of the narratives we've seen over t…

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
