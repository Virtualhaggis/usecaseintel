# [CRIT] [GHSA / CRITICAL] GHSA-6626-79jh-5ccr: Duplicate Advisory: phpMyFAQ enables unauthenticated 2FA brute-force attack via /admin/check acceptance of arbitrary user-id

**Source:** GitHub Security Advisories
**Published:** 2026-05-15
**Article:** https://github.com/advisories/GHSA-6626-79jh-5ccr

## Threat Profile

Duplicate Advisory: phpMyFAQ enables unauthenticated 2FA brute-force attack via /admin/check acceptance of arbitrary user-id

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-9pq7-mfwh-xx2j. This link is maintained to preserve external references.

### Original Description
phpMyFAQ before 4.1.2 contains an improper restriction of excessive authentication attempts vulnerability in the /admin/check endpoint, which accepts arbitrary user-id parameters withou…

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
