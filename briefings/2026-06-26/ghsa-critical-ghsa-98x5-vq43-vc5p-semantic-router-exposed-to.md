# [CRIT] [GHSA / CRITICAL] GHSA-98x5-vq43-vc5p: semantic-router exposed to compromised litellm wheel (CVE-2026-42208) via unbounded transitive pin

**Source:** GitHub Security Advisories
**Published:** 2026-06-26
**Article:** https://github.com/advisories/GHSA-98x5-vq43-vc5p

## Threat Profile

semantic-router exposed to compromised litellm wheel (CVE-2026-42208) via unbounded transitive pin

## Impact
semantic-router versions 0.1.8 through 0.1.14 declare `litellm>=1.61.3` with no upper bound. During the window in which `litellm==1.82.8` was the latest release on PyPI, a fresh install of any affected semantic-router version could resolve to that compromised wheel.

The malicious `litellm==1.82.8` wheel ships a `litellm_init.pth` file that executes on Python interpreter startup — no imp…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42208`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-42208`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
