# [HIGH] CISA Warns of Linux Kernel Improper Authentication Vulnerability Exploited in Attacks

**Source:** Cyber Security News
**Published:** 2026-06-07
**Article:** https://cybersecuritynews.com/linux-kernel-improper-authentication-vulnerability/

## Threat Profile

The U.S. Cybersecurity and Infrastructure Security Agency (CISA) has added a critical Linux kernel vulnerability, tracked as CVE-2022-0492, to its Known Exploited Vulnerabilities (KEV) catalog, warning that the flaw is being actively leveraged in real-world attacks. The issue, categorized as improper authentication, affects Linux systems using the cgroups v1 release_agent feature and may allow attackers [&#8230;] The post CISA Warns of Linux Kernel Improper Authentication Vulnerability Exploited…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-0492`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-0492`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
