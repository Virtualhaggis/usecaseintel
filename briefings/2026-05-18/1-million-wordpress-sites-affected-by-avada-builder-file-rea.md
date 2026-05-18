# [HIGH] 1 Million WordPress Sites Affected by Avada Builder File Read and SQL Injection Flaws

**Source:** Cyber Security News
**Published:** 2026-05-18
**Article:** https://cybersecuritynews.com/avada-builder-plugin-vulnerability/

## Threat Profile

Home Cyber Security News 
1 Million WordPress Sites Affected by Avada Builder File Read and SQL Injection Flaws 
By Abinaya 
May 18, 2026 




A widely used WordPress plugin powering over one million websites has been hit by two serious vulnerabilities that could allow attackers to  steal sensitive data and access server files.
Security researchers warn that the flaws in the Avada Builder plugin could be actively exploited if sites remain unpatched.
The issues, discovered by researcher Rafie…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-4782`
- **CVE:** `CVE-2026-4798`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-4782`, `CVE-2026-4798`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
