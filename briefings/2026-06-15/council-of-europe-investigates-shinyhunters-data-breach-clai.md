# [HIGH] Council of Europe investigates ShinyHunters data breach claims

**Source:** BleepingComputer
**Published:** 2026-06-15
**Article:** https://www.bleepingcomputer.com/news/security/council-of-europe-investigates-shinyhunters-data-breach-claims/

## Threat Profile

Council of Europe investigates ShinyHunters data breach claims 
By Sergiu Gatlan 
June 15, 2026
12:37 PM
0 
The Council of Europe, the continent's oldest intergovernmental body, is probing claims of a data breach made by the ShinyHunters extortion group over the weekend.
As Europe's leading human rights organization, the Council represents 46 European member states and a population of over 700 million people, promoting democracy and the rule of law across Europe and beyond.
When asked to confirm…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35273`
- **Domain (defanged):** `coe.int`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-35273`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `coe.int`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
