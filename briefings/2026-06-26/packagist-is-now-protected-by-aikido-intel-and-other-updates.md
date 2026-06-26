# [MED] Packagist is now protected by Aikido Intel and other updates to the PHP registry

**Source:** Aikido
**Published:** 2026-06-26
**Article:** https://www.aikido.dev/blog/composer-protected-aikido-packagist

## Threat Profile

Blog Product & Company Updates Packagist is now protected by Aikido Intel and other updates to the PHP registry Packagist is now protected by Aikido Intel and other updates to the PHP registry Written by Dania Durnas Published on: Jun 26, 2026 Running an open source registry means fighting fires. Another maintainer’s account gets popped, another malicious package. The takedown is always one upload behind. The job never ends, and most registries, run by small teams with little cash, are often too…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `flipboxstudio.info`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `flipboxstudio.info`


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
