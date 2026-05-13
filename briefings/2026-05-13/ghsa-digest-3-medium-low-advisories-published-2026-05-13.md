# [MED] [GHSA / DIGEST] 3 medium/low advisories published 2026-05-13

**Source:** GitHub Security Advisories
**Published:** 2026-05-13
**Article:** https://github.com/advisories?published=2026-05-13&severity=medium,low&type=reviewed

## Threat Profile

Daily roundup of 3 medium- and low-severity GitHub Security Advisories reviewed on 2026-05-13. Individual high-severity advisories still get their own cards.

- [MEDIUM] CVE-2026-44681: Authlib OIDC Implicit/Hybrid Authorization Vulnerable to Open Redirect  (affects: pip:authlib (vuln = 1.7.0))
- [MEDIUM] CVE-2026-44720: OpenLearnX: Critical Authentication Bypass via JWT Signature Verification Disabled Leading to Account Takeover  (affects: npm:openlearnx (vuln < 2.0.4))
- [   LOW] CVE-2026-4502…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-44681`
- **CVE:** `CVE-2026-44720`
- **CVE:** `CVE-2026-45028`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-44681`, `CVE-2026-44720`, `CVE-2026-45028`


## Why this matters

Severity classified as **MED** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
