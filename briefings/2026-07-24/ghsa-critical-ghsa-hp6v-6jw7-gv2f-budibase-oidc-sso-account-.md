# [CRIT] [GHSA / CRITICAL] GHSA-hp6v-6jw7-gv2f: Budibase: OIDC SSO account takeover: incoming identity linked by email without checking email_verified

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-hp6v-6jw7-gv2f

## Threat Profile

Budibase: OIDC SSO account takeover: incoming identity linked by email without checking email_verified

### Summary
Budibase's OIDC SSO login links an incoming SSO identity to an existing Budibase account **by email address alone**, without ever checking the `email_verified` claim of the OIDC ID token. Budibase first tries to match the IdP `sub`; when that misses (any fresh attacker IdP account) it silently falls back to matching by the `email` claim and **merges into the existing account by ema…

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
