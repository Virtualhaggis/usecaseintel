# [LOW] [GHSA / CRITICAL] GHSA-m8wm-r5vq-qjpg: Duplicate Advisory: OpenClaw: Gateway HTTP endpoints re-resolve bearer auth after SecretRef rotation

**Source:** GitHub Security Advisories
**Published:** 2026-05-06
**Article:** https://github.com/advisories/GHSA-m8wm-r5vq-qjpg

## Threat Profile

Duplicate Advisory: OpenClaw: Gateway HTTP endpoints re-resolve bearer auth after SecretRef rotation

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-xmxx-7p24-h892. This link is maintained to preserve external references.

### Original Description
OpenClaw before 2026.4.15 captures resolved bearer-auth configuration at startup, allowing revoked tokens to remain valid after SecretRef rotation. Gateway HTTP and WebSocket handlers fail to re-resolve authen…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- _Narrative-keyword inference returned no technique mappings; review article for ATT&CK relevance manually._

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

_No actionable hunts can be derived from the RSS summary alone. The article may still warrant manual review — open the source link for actor attribution, IOCs in the body, and TTP detail._


## Why this matters

Severity classified as **LOW** based on: 0 use case(s) fired, 0 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
