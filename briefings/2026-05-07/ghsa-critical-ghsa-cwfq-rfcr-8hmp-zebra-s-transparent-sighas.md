# [CRIT] [GHSA / CRITICAL] GHSA-cwfq-rfcr-8hmp: Zebra's Transparent SIGHASH_SINGLE Handling Diverges from zcashd for Corresponding Outputs

**Source:** GitHub Security Advisories
**Published:** 2026-05-07
**Article:** https://github.com/advisories/GHSA-cwfq-rfcr-8hmp

## Threat Profile

Zebra's Transparent SIGHASH_SINGLE Handling Diverges from zcashd for Corresponding Outputs

# `Zebra` Transparent `SIGHASH_SINGLE` Corresponding-Output Handling Diverges From `zcashd`

### Summary
For V5+ transparent spends, `Zebra` and `zcashd` disagree on the same consensus rule: `SIGHASH_SINGLE` must fail when the input index has no corresponding output. `zcashd` treats this as consensus-invalid under ZIP-244, while `Zebra`'s transparent verification path computes a digest for the missing-out…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- _Narrative-keyword inference returned no technique mappings; review article for ATT&CK relevance manually._

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

_No actionable hunts can be derived from the RSS summary alone. The article may still warrant manual review — open the source link for actor attribution, IOCs in the body, and TTP detail._


## Why this matters

Severity classified as **CRIT** based on: 0 use case(s) fired, 0 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
