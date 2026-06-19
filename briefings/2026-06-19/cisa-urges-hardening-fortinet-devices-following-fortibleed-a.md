# [MED] CISA Urges Hardening Fortinet Devices Following FortiBleed Attack

**Source:** Cyber Security News
**Published:** 2026-06-19
**Article:** https://cybersecuritynews.com/cisa-urges-hardening-fortinet-devices/

## Threat Profile

CISA has issued an urgent advisory warning organizations to secure their Fortinet devices following reports of a large-scale credential exposure campaign known as “FortiBleed.” The alert comes after threat actors were found exploiting compromised credentials linked to tens of thousands of internet-facing Fortinet systems worldwide. According to CISA, the FortiBleed activity involves leaked credentials associated [&#8230;] The post CISA Urges Hardening Fortinet Devices Following FortiBleed Attack…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-55591`
- **CVE:** `CVE-2025-59718`
- **CVE:** `CVE-2025-59719`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-55591`, `CVE-2025-59718`, `CVE-2025-59719`


## Why this matters

Severity classified as **MED** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
