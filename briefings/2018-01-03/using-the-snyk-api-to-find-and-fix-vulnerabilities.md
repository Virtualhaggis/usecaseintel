# [HIGH] Using the Snyk API to find and fix vulnerabilities

**Source:** Snyk
**Published:** 2018-01-03
**Article:** https://snyk.io/blog/using-the-snyk-api-to-find-and-fix-vulnerabilities/

## Threat Profile

Snyk Blog In this article
Written by Josh Emerson 
January 3, 2018
0 mins read Illustration by Lou Reade. 
In this blog post, you will learn how to use the Snyk API to retrieve all the issues associated with a given project. There are several reasons you may find it valuable, notably pulling them into your reports and dashboards, giving management and developers visibility into their vulnerability status within the portals and workflows they’re already using.
Over the following steps, we will us…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `305f2ddcd4eff7cc7c518aca6bb2b2d2daad8fef`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `305f2ddcd4eff7cc7c518aca6bb2b2d2daad8fef`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
