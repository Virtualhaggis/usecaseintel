# [LOW] Android Banking Trojan OverlayPhantom Abuses Accessibility Service to Control Devices

**Source:** Cyber Security News
**Published:** 2026-06-01
**Article:** https://cybersecuritynews.com/android-banking-trojan-overlayphantom/

## Threat Profile

A dangerous new Android banking trojan called OverlayPhantom has been quietly targeting users across ten countries, placing banking credentials, financial data, and cryptocurrency accounts at serious risk. The malware has been active since May 2025 and spreads through malicious links disguised as downloads from trusted, well-known applications. What makes OverlayPhantom particularly alarming is how it [&#8230;] The post Android Banking Trojan OverlayPhantom Abuses Accessibility Service to Contro…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `199.217.99.122`
- **Domain (defanged):** `bitlrewards-app.com`
- **SHA256:** `9ef37376bfaa18e193cc72218924ad8ebf56d2667d348f0eae5ae6ec45ab8775`
- **SHA256:** `f8b614a2918378063d6e6655b676ceb52ae65b1510e2cc08087fcac31acb7aeb`
- **SHA256:** `8ddc1f2a75f3d5b5bd054a5367bd5015ebc90f3453d63c7cce438c12dc2ae86a`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `199.217.99.122`, `bitlrewards-app.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9ef37376bfaa18e193cc72218924ad8ebf56d2667d348f0eae5ae6ec45ab8775`, `f8b614a2918378063d6e6655b676ceb52ae65b1510e2cc08087fcac31acb7aeb`, `8ddc1f2a75f3d5b5bd054a5367bd5015ebc90f3453d63c7cce438c12dc2ae86a`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
