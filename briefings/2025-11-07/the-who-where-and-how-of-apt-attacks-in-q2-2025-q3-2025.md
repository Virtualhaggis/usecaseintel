# [CRIT] The who, where, and how of APT attacks in Q2 2025–Q3 2025

**Source:** ESET WeLiveSecurity
**Published:** 2025-11-07
**Article:** https://www.welivesecurity.com/en/videos/who-where-how-apt-attacks-q2-2025-q3-2025/

## Threat Profile

The who, where, and how of APT attacks in Q2 2025–Q3 2025 
Video
The who, where, and how of APT attacks in Q2 2025–Q3 2025 ESET Chief Security Evangelist Tony Anscombe highlights some of the key findings from the latest issue of the ESET APT Activity Report
Editor 
07 Nov 2025 
Yesterday, the ESET research team released the latest issue of its APT Activity Report  that summarizes and contextualizes the cyber-operations of some of the world's most notorious state-aligned hacking groups from April…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-8088`
- **Domain (defanged):** `esetsmart.com`
- **Domain (defanged):** `esetscanner.com`
- **Domain (defanged):** `esetremover.com`
- **SHA256:** `e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389`
- **SHA256:** `bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-8088`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `esetsmart.com`, `esetscanner.com`, `esetremover.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `e77afc29d52cbf4bedb8bc92017fb3ddd051d8acc9b106b627e10b8285ab7389`, `bf50442dedeb6a715de82177eb7e24daed3f3e45d6dcd186bb360675d07ac047`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
