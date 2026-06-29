# [HIGH] Nissan discloses employee data breach linked to Oracle zero-day attacks

**Source:** BleepingComputer
**Published:** 2026-06-29
**Article:** https://www.bleepingcomputer.com/news/security/nissan-discloses-employee-data-breach-linked-to-oracle-zero-day-attacks/

## Threat Profile

Nissan discloses employee data breach linked to Oracle zero-day attacks 
By Lawrence Abrams 
June 29, 2026
04:40 PM
0 


Nissan is warning that it suffered a data breach affecting current and former employees after threat actors exploited an Oracle PeopleSoft vulnerability in data theft attacks previously linked to the ShinyHunters extortion group.


In breach notifications filed with the California Attorney General's Office, Oracle says these data theft attacks impacted hundreds of companie…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35273`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-35273`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
