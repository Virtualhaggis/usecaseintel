# [HIGH] Microsoft Defender 'RoguePlanet' zero-day grants SYSTEM privileges

**Source:** BleepingComputer
**Published:** 2026-06-09
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/

## Threat Profile

Microsoft Defender 'RoguePlanet' zero-day grants SYSTEM privileges 
By Lawrence Abrams 
June 9, 2026
07:11 PM
0 


A security researcher has released a new Microsoft Defender zero-day exploit named "RoguePlanet" just hours after Microsoft fixed two previously disclosed flaws during June 2026 Patch Tuesday.


The researcher, known as Nightmare Eclipse, says the new vulnerability affects fully patched Windows 10 and Windows 11 devices, allowing attackers to spawn a command prompt with SYSTEM p…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33825`
- **CVE:** `CVE-2026-41091`
- **CVE:** `CVE-2026-45585`
- **Domain (defanged):** `projectnightcrawler.dev`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33825`, `CVE-2026-41091`, `CVE-2026-45585`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `projectnightcrawler.dev`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
