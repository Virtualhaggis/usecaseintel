# [CRIT] [GHSA / CRITICAL] GHSA-82fg-2r99-h7v6: Duplicate Advisory: PickleScan's pkgutil.resolve_name has a universal blocklist bypass

**Source:** GitHub Security Advisories
**Published:** 2026-06-17
**Article:** https://github.com/advisories/GHSA-82fg-2r99-h7v6

## Threat Profile

Duplicate Advisory: PickleScan's pkgutil.resolve_name has a universal blocklist bypass

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-vvpj-8cmc-gx39. This link is maintained to preserve external references.

### Original Description
picklescan before 1.0.4 fails to block pkgutil.resolve_name, allowing attackers to bypass the entire blocklist by resolving any dangerous function through indirect REDUCE calls. Remote attackers can invoke any blocked funct…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-3490`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-3490`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
