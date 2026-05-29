# [HIGH] Manage security issues in Jira with Snyk Security in Jira Cloud

**Source:** Snyk
**Published:** 2023-08-09
**Article:** https://snyk.io/blog/snyk-security-in-jira-cloud/

## Threat Profile

Snyk Blog In this article
Written by LaToya Muff 
August 9, 2023
0 mins read Incorporating security into the software development lifecycle helps ensure the creation of secure and robust software applications from the very beginning. To further evolve our security offerings in the developer community, we announced our partnership with Atlassian to introduce Snyk Security in Jira Cloud as a part of the Security in Jira launch in June. 
Snyk started gradually rolling out the Jira Security App and …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-22967`
- **CVE:** `CVE-2022-229`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-22967`, `CVE-2022-229`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
