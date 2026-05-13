# [MED] [GHSA / CRITICAL] GHSA-9h64-2846-7x7f: Axonflow fixed bugs by implementing multi-tenant isolation and access-control hardening

**Source:** GitHub Security Advisories
**Published:** 2026-05-06
**Article:** https://github.com/advisories/GHSA-9h64-2846-7x7f

## Threat Profile

Axonflow fixed bugs by implementing multi-tenant isolation and access-control hardening

## Summary

Eight independently-filed bug fixes in the v7.1.3 → v7.5.0 release window collectively close a set of multi-tenant isolation, access-control, and policy-enforcement defects in the AxonFlow platform. They are filed as a single consolidated advisory because the recommended remediation is a single platform upgrade.

## Affected versions

`< 7.5.0`. Specific items affect different earlier minors; see…

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
