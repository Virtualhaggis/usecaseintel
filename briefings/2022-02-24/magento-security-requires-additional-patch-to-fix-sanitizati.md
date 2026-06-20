# [HIGH] Magento security requires additional patch to fix sanitization vulnerability

**Source:** Snyk
**Published:** 2022-02-24
**Article:** https://snyk.io/blog/magento-vulnerability-cve-2022-24087-sanitization/

## Threat Profile

Snyk Blog In this article
Written by DeveloperSteve Coochin 
February 24, 2022
0 mins read As technology folks, we are often under a lot of pressure to fix some deployed code, update an infrastructure component, or patch some code. Often it's with little notice and needs to be done 5 minutes ago. The gamble with any “zero turnaround” is the rush to fix now vs. taking the time to test and check.
Recently, a critical patch was released for Magento Ecommerce , Magento Open Source, and Adobe Commerc…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-24086`
- **CVE:** `CVE-2022-24087`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-24086`, `CVE-2022-24087`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
