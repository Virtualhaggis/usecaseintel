# [MED] Multiple Splunk Enterprise Vulnerabilities Allow Attackers to Execute Malicious Script

**Source:** Cyber Security News
**Published:** 2026-06-11
**Article:** https://cybersecuritynews.com/multiple-splunk-enterprise-vulnerabilities/

## Threat Profile

Multiple high and critical vulnerabilities in Splunk Enterprise could allow attackers to execute malicious scripts, exfiltrate sensitive data, and perform unauthorized file operations, according to a series of security advisories released on June 10, 2026. The most severe flaw, tracked as CVE-2026-20253, carries a CVSS score of 9.8 and affects Splunk Enterprise versions below 10.2.4 [&#8230;] The post Multiple Splunk Enterprise Vulnerabilities Allow Attackers to Execute Malicious Script appeared…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-20251`
- **CVE:** `CVE-2026-20252`
- **CVE:** `CVE-2026-20253`
- **CVE:** `CVE-2026-20254`
- **CVE:** `CVE-2026-20255`
- **CVE:** `CVE-2026-20256`
- **CVE:** `CVE-2026-20257`
- **CVE:** `CVE-2026-20258`
- **CVE:** `CVE-2026-20259`
- **CVE:** `CVE-2026-20260`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-20251`, `CVE-2026-20252`, `CVE-2026-20253`, `CVE-2026-20254`, `CVE-2026-20255`, `CVE-2026-20256`, `CVE-2026-20257`, `CVE-2026-20258` _(+2 more)_


## Why this matters

Severity classified as **MED** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
