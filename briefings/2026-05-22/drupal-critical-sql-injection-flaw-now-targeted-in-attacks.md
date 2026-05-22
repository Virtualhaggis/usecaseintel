# [HIGH] Drupal: Critical SQL injection flaw now targeted in attacks

**Source:** BleepingComputer
**Published:** 2026-05-22
**Article:** https://www.bleepingcomputer.com/news/security/drupal-critical-sql-injection-flaw-now-targeted-in-attacks/

## Threat Profile

Drupal: Critical SQL injection flaw now targeted in attacks 
By Bill Toulas 
May 22, 2026
09:14 AM
0 
Drupal is warning that hackers are attempting to exploit a "highly critical" SQL injection vulnerability announced earlier this week.
The content management system (CMS) project published a PSA on May 18, urging administrators to reserve time for core updates that addressed an issue that threat actors might start exploiting "within hours or days."
The flaw is now tracked as CVE-2026-9082 and was…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-9082`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-9082`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
