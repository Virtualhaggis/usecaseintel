# [HIGH] Ubiquiti patches three max severity UniFi OS vulnerabilities

**Source:** BleepingComputer
**Published:** 2026-05-22
**Article:** https://www.bleepingcomputer.com/news/security/ubiquiti-patches-three-max-severity-unifi-os-vulnerabilities/

## Threat Profile

Ubiquiti patches three max severity UniFi OS vulnerabilities 
By Sergiu Gatlan 
May 22, 2026
08:00 AM
2 


Ubiquiti has released security updates to patch three maximum severity vulnerabilities in UniFi OS that can be exploited by remote attackers without privileges.


UniFi OS is a unified operating system that powers UniFi Consoles and helps manage IT infrastructure, including networking, security, and other services, as well as UniFi applications such as UniFi Network, UniFi Protect, UniF…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-34908`
- **CVE:** `CVE-2026-34909`
- **CVE:** `CVE-2026-34910`
- **CVE:** `CVE-2026-33000`
- **CVE:** `CVE-2026-34911`
- **CVE:** `CVE-2026-22557`
- **CVE:** `CVE-2026-22558`
- **CVE:** `CVE-2010-5330`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-34908`, `CVE-2026-34909`, `CVE-2026-34910`, `CVE-2026-33000`, `CVE-2026-34911`, `CVE-2026-22557`, `CVE-2026-22558`, `CVE-2010-5330`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
