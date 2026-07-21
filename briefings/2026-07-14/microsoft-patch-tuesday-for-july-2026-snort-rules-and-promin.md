# [HIGH] Microsoft Patch Tuesday for July 2026 — Snort rules and prominent vulnerabilities

**Source:** Cisco Talos
**Published:** 2026-07-14
**Article:** https://blog.talosintelligence.com/microsoft-patch-tuesday-july-2026/

## Threat Profile

Microsoft Patch Tuesday for July 2026 — Snort rules and prominent vulnerabilities 
By 
Cisco Talos 
Tuesday, July 14, 2026 16:27
Patch Tuesday
Microsoft has released its monthly security update for July 2026, which includes 622 vulnerabilities affecting a range of products, including 57 that Microsoft marked as "critical".
Microsoft notes that two of the vulnerabilities disclosed this month have been exploited in the wild.
CVE-2026-56155 is an important-severity elevation of privilege vulnerabil…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-56155`
- **CVE:** `CVE-2026-56164`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-56155`, `CVE-2026-56164`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
