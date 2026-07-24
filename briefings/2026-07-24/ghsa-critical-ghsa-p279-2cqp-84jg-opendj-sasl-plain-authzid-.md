# [CRIT] [GHSA / CRITICAL] GHSA-p279-2cqp-84jg: OpenDJ SASL PLAIN authzid bypassing the proxy ACI scope check

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-p279-2cqp-84jg

## Threat Profile

OpenDJ SASL PLAIN authzid bypassing the proxy ACI scope check

### Summary
When a SASL PLAIN bind supplies an authorization identity (authzid) that resolves to a **different** user, PlainSASLMechanismHandler verified only the PROXIED_AUTH privilege and never evaluated the "proxy" access-control right (the mayProxy ACI scope check). As a result, any account holding the proxied-auth privilege could assume **any resolvable non-root identity** without being granted a proxy ACI for that target.

This…

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
