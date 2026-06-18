# [CRIT] [GHSA / CRITICAL] GHSA-6v84-v468-3c7f: Duplicate Advisory: Picklescan has Incomplete List of Disallowed Inputs

**Source:** GitHub Security Advisories
**Published:** 2026-06-17
**Article:** https://github.com/advisories/GHSA-6v84-v468-3c7f

## Threat Profile

Duplicate Advisory: Picklescan has Incomplete List of Disallowed Inputs

## Duplicate Advisory

This advisory has been withdrawn because it is a duplicate of GHSA-84r2-jw7c-4r5q. This link is maintained to preserve external references.

## Original Description
picklescan before 0.0.33 contains an incomplete deny-list that fails to block pydoc.locate and operator.methodcaller functions, allowing attackers to bypass security checks. Remote attackers can craft malicious pickle files using these unb…

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
