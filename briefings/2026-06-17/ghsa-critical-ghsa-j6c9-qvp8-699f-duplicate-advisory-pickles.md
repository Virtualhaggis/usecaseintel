# [CRIT] [GHSA / CRITICAL] GHSA-j6c9-qvp8-699f: Duplicate Advisory: picklescan missing detection by simple obfuscation of a `builtins.eval` call

**Source:** GitHub Security Advisories
**Published:** 2026-06-17
**Article:** https://github.com/advisories/GHSA-j6c9-qvp8-699f

## Threat Profile

Duplicate Advisory: picklescan missing detection by simple obfuscation of a `builtins.eval` call

## Duplicate Advisory

This advisory has been withdrawn because it is a duplicate of GHSA-9m3x-qqw2-h32h. This link is maintained to preserve external references.

## Original Description
picklescan before 1.0.1 contains an unsafe deserialization vulnerability allowing unauthenticated users to execute arbitrary code by hiding eval calls nested under callable objects via getattr. Attackers can embed …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-53874`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-53874`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
