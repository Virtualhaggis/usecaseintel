# [HIGH] SAP fixes critical flaws in NetWeaver and Commerce Cloud

**Source:** BleepingComputer
**Published:** 2026-06-09
**Article:** https://www.bleepingcomputer.com/news/security/sap-fixes-critical-flaws-in-netweaver-and-commerce-cloud/

## Threat Profile

SAP fixes critical flaws in NetWeaver and Commerce Cloud 
By Bill Toulas 
June 9, 2026
03:36 PM
0 


SAP has released fixes for 15 vulnerabilities as part of its June 2026 Security Patch package, including four critical-severity flaws affecting SAP NetWeaver and SAP Commerce Cloud.


NetWeaver is SAP's core application platform and middleware stack that provides the foundation for many SAP business applications, including ERP systems, handling functions such as application serving, integrati…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-44748`
- **CVE:** `CVE-2026-27671`
- **CVE:** `CVE-2026-22732`
- **CVE:** `CVE-2026-40128`
- **CVE:** `CVE-2026-29145`
- **CVE:** `CVE-2026-44751`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-44748`, `CVE-2026-27671`, `CVE-2026-22732`, `CVE-2026-40128`, `CVE-2026-29145`, `CVE-2026-44751`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
