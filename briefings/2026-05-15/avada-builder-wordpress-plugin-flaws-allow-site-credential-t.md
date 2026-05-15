# [HIGH] Avada Builder WordPress plugin flaws allow site credential theft

**Source:** BleepingComputer
**Published:** 2026-05-15
**Article:** https://www.bleepingcomputer.com/news/security/avada-builder-wordpress-plugin-flaws-allow-site-credential-theft/

## Threat Profile

Avada Builder WordPress plugin flaws allow site credential theft 
By Bill Toulas 
May 15, 2026
11:56 AM
0 


Two vulnerabilities in the Avada Builder plugin for WordPress, with an estimated one million active installations, allow hackers to read arbitrary files and extract sensitive information from the database.


One of the flaws is tracked as CVE-2026-4782 and can be exploited in all versions of the plugin through 3.15.2 by an authenticated users with at least subscriber-level access to r…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-4782`
- **CVE:** `CVE-2026-4798`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-4782`, `CVE-2026-4798`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
