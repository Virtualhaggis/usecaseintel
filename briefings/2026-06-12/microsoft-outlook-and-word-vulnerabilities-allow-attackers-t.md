# [HIGH] Microsoft Outlook and Word Vulnerabilities Allow Attackers to Execute Malicious Code

**Source:** Cyber Security News
**Published:** 2026-06-12
**Article:** https://cybersecuritynews.com/microsoft-outlook-and-word-vulnerabilities/

## Threat Profile

Microsoft released critical fixes for three closely related remote code execution (RCE) vulnerabilities in Microsoft Outlook and Word that stem from low‑level memory‑safety flaws in the Word rendering engine and its integration with Outlook Classic. These bugs, tracked as CVE‑2026‑45456, CVE‑2026‑45458, and CVE‑2026‑47635, are rated Critical with a CVSS v3.1 base score of 8.4, reflecting [&#8230;] The post Microsoft Outlook and Word Vulnerabilities Allow Attackers to Execute Malicious Code appea…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45456`
- **CVE:** `CVE-2026-45458`
- **CVE:** `CVE-2026-47635`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45456`, `CVE-2026-45458`, `CVE-2026-47635`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
