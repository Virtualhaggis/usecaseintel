# [CRIT] [GHSA / CRITICAL] GHSA-q6x4-v3qx-85qw: Budibase: SQL Injection via `multipleStatements: true`

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-q6x4-v3qx-85qw

## Threat Profile

Budibase: SQL Injection via `multipleStatements: true`

## Summary
A critical SQL injection vulnerability was discovered in Budibase's MySQL integration that allows remote attackers to execute arbitrary SQL commands.

## Details
### Vulnerability Type
SQL Injection

### Description
The MySQL integration component in Budibase is configured with `multipleStatements: true`, enabling execution of multiple SQL statements in a single query. Attackers can inject malicious SQL commands through user inpu…

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
