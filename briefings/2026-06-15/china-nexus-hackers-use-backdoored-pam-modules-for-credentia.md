# [MED] China-Nexus Hackers Use Backdoored PAM Modules for Credential Theft and Authentication Bypass

**Source:** Cyber Security News
**Published:** 2026-06-15
**Article:** https://cybersecuritynews.com/china-nexus-hackers-use-backdoored-pam-modules/

## Threat Profile

A sophisticated China-linked threat actor known as Velvet Ant has been running a long-term cyber intrusion inside a major organization&#8217;s internal network, going undetected for nearly a decade. The campaign, now called Operation Highland, revealed a level of patience and technical depth rarely seen in publicly documented intrusions. What made this attack particularly alarming was [&#8230;] The post China-Nexus Hackers Use Backdoored PAM Modules for Credential Theft and Authentication Bypass…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-20399`
- **Domain (defanged):** `gs.thc.org`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-20399`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `gs.thc.org`


## Why this matters

Severity classified as **MED** based on: CVE present, IOCs present, 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
