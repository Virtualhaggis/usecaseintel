# [HIGH] Microsoft Patch Tuesday for May 2026 — Snort rules and prominent vulnerabilities

**Source:** Cisco Talos
**Published:** 2026-05-12
**Article:** https://blog.talosintelligence.com/microsoft-patch-tuesday-may-2026/

## Threat Profile

Microsoft Patch Tuesday for May 2026 — Snort rules and prominent vulnerabilities 
By 
Jaeson Schultz 
Tuesday, May 12, 2026 15:57
Patch Tuesday
By   Jaeson Schultz  
Microsoft has released its monthly security update for May 2026, which includes 137 vulnerabilities affecting a range of products, including 31 that Microsoft marked as “critical”. 
In this month's release, Microsoft has not observed any of the included vulnerabilities being actively exploited in the wild. Out of 31 "critical" entri…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-32161`
- **CVE:** `CVE-2026-33109`
- **CVE:** `CVE-2026-33844`
- **CVE:** `CVE-2026-35421`
- **CVE:** `CVE-2026-40358`
- **CVE:** `CVE-2026-40361`
- **CVE:** `CVE-2026-40363`
- **CVE:** `CVE-2026-40364`
- **CVE:** `CVE-2026-40365`
- **CVE:** `CVE-2026-40366`
- **CVE:** `CVE-2026-40367`
- **CVE:** `CVE-2026-40403`
- **CVE:** `CVE-2026-41089`
- **CVE:** `CVE-2026-41096`
- **CVE:** `CVE-2026-42831`
- **CVE:** `CVE-2026-42898`
- **CVE:** `CVE-2026-33835`
- **CVE:** `CVE-2026-33837`
- **CVE:** `CVE-2026-33840`
- **CVE:** `CVE-2026-33841`
- **CVE:** `CVE-2026-35416`
- **CVE:** `CVE-2026-35417`
- **CVE:** `CVE-2026-40369`
- **CVE:** `CVE-2026-40397`
- **CVE:** `CVE-2026-40398`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-32161`, `CVE-2026-33109`, `CVE-2026-33844`, `CVE-2026-35421`, `CVE-2026-40358`, `CVE-2026-40361`, `CVE-2026-40363`, `CVE-2026-40364` _(+17 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
