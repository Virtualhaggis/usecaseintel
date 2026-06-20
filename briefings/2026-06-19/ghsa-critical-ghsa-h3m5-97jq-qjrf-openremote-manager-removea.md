# [CRIT] [GHSA / CRITICAL] GHSA-h3m5-97jq-qjrf: OpenRemote Manager: removeAlarms cross-realm IDOR (bulk delete)

**Source:** GitHub Security Advisories
**Published:** 2026-06-19
**Article:** https://github.com/advisories/GHSA-h3m5-97jq-qjrf

## Threat Profile

OpenRemote Manager: removeAlarms cross-realm IDOR (bulk delete)

### Summary
OpenRemote Manager is vulnerable to a cross-tenant Insecure Direct
Object Reference (IDOR) in the bulk alarm deletion endpoint. An
authenticated user in any realm can delete alarms belonging to other
realms (tenants) by supplying arbitrary alarm IDs. The vulnerability
exists because the bulk removeAlarms() method only verifies that the
caller's own realm is active and accessible, but never checks whether
the targeted al…

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
