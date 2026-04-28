# [HIGH] ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025

**Source:** ESET WeLiveSecurity
**Published:** 2026-01-23
**Article:** https://www.welivesecurity.com/en/eset-research/eset-research-sandworm-cyberattack-poland-power-grid-late-2025/

## Threat Profile

ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025 
ESET Research
ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025 The attack involved data-wiping malware that ESET researchers have now analyzed and named DynoWiper
ESET Research 
23 Jan 2026 
 •  
, 
2 min. read 
UPDATE (January 30 th , 2026): For a technical breakdown of the incident affecting a company in Poland’s energy sector, refer to this blogpost . 
In late 2025, Poland’s energy sy…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
