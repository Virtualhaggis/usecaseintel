# [MED] [GHSA / CRITICAL] GHSA-cwfq-rfcr-8hmp: Zebra's Transparent SIGHASH_SINGLE Handling Diverges from zcashd for Corresponding Outputs

**Source:** GitHub Security Advisories
**Published:** 2026-05-07
**Article:** https://github.com/advisories/GHSA-cwfq-rfcr-8hmp

## Threat Profile

Zebra's Transparent SIGHASH_SINGLE Handling Diverges from zcashd for Corresponding Outputs

# `Zebra` Transparent `SIGHASH_SINGLE` Corresponding-Output Handling Diverges From `zcashd`

### Summary
For V5+ transparent spends, `Zebra` and `zcashd` disagree on the same consensus rule: `SIGHASH_SINGLE` must fail when the input index has no corresponding output. `zcashd` treats this as consensus-invalid under ZIP-244, while `Zebra`'s transparent verification path computes a digest for the missing-out…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `2c63e9aa08cb170b0feb374161bea94720c3e1f5`
- **SHA1:** `a905fa19e3a91c7b4ead331e2709e6dec5db12cb`
- **SHA1:** `c3425f9c3c7f6deb20720bb78b18f35fbbed8edd`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2c63e9aa08cb170b0feb374161bea94720c3e1f5`, `a905fa19e3a91c7b4ead331e2709e6dec5db12cb`, `c3425f9c3c7f6deb20720bb78b18f35fbbed8edd`


## Why this matters

Severity classified as **MED** based on: IOCs present, 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
