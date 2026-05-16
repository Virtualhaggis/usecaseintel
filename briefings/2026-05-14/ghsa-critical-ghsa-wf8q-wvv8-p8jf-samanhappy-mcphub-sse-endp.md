# [CRIT] [GHSA / CRITICAL] GHSA-wf8q-wvv8-p8jf: @samanhappy/mcphub: SSE Endpoint Accepts Arbitrary Username from URL Path Without Authentication, Enabling User Impersonation

**Source:** GitHub Security Advisories
**Published:** 2026-05-14
**Article:** https://github.com/advisories/GHSA-wf8q-wvv8-p8jf

## Threat Profile

@samanhappy/mcphub: SSE Endpoint Accepts Arbitrary Username from URL Path Without Authentication, Enabling User Impersonation

### Summary

A critical identity spoofing vulnerability in MCPHub allows any unauthenticated user to impersonate any other user — including administrators — on SSE (Server-Sent Events) and MCP transport endpoints. The server accepts a username from the URL path parameter and creates an internal user session without any database validation, token verification, or authenti…

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
