# [HIGH] Find Log4Shell vulnerabilities in your unmanaged and shaded jars with the Snyk CLI

**Source:** Snyk
**Published:** 2021-12-18
**Article:** https://snyk.io/blog/new-snyk-cli-command-finds-log4shell-in-unmanaged-undeclared-java-code/

## Threat Profile

Snyk Blog In this article
Written by Michal Brutvan 
December 18, 2021
0 mins read As you may be aware — the Log4Shell vulnerability identified as CVE-2021-44228 and CVE-2021-45046 was disclosed on Friday (December 10th, 2021) for Apache’s Log4j logging framework. Snyk’s CLI is a powerful tool to begin with, giving you the ability to find Log4j CVEs if the library is included directly or transitively within your application. However, if the Log4j library was not disclosed in the manifest file, f…

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
