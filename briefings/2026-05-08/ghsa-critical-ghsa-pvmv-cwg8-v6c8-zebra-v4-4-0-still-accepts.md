# [MED] [GHSA / CRITICAL] GHSA-pvmv-cwg8-v6c8: Zebra v4.4.0 still accepts V5 SIGHASH_SINGLE without a corresponding output

**Source:** GitHub Security Advisories
**Published:** 2026-05-08
**Article:** https://github.com/advisories/GHSA-pvmv-cwg8-v6c8

## Threat Profile

Zebra v4.4.0 still accepts V5 SIGHASH_SINGLE without a corresponding output

# Consensus Divergence in V5 Transparent SIGHASH_SINGLE With No Corresponding Output

## Summary

Zebra failed to enforce a ZIP-244 consensus rule for V5 transparent transactions: when an input is signed with `SIGHASH_SINGLE` and there is no transparent output at the same index as that input, validation must fail. Zebra instead asked the underlying sighash library to compute a digest, and that library produced a digest …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- _Narrative-keyword inference returned no technique mappings; review article for ATT&CK relevance manually._

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

_No actionable hunts can be derived from the RSS summary alone. The article may still warrant manual review — open the source link for actor attribution, IOCs in the body, and TTP detail._


## Why this matters

Severity classified as **MED** based on: 0 use case(s) fired, 0 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
