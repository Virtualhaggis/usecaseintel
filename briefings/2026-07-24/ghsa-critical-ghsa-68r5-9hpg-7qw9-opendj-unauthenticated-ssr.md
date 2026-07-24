# [CRIT] [GHSA / CRITICAL] GHSA-68r5-9hpg-7qw9: OpenDJ unauthenticated SSRF, local file read and unbounded-read DoS in the DSMLv2 gateway

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-68r5-9hpg-7qw9

## Threat Profile

OpenDJ unauthenticated SSRF, local file read and unbounded-read DoS in the DSMLv2 gateway

The DSMLv2 SOAP gateway (opendj-dsml-servlet) in OpenIdentityPlatform OpenDJ through 5.1.1 dereferences attacker-supplied xsd:anyURI values server-side without a scheme allowlist, egress filtering, or a size cap, and is reachable without authentication by default. A remote unauthenticated attacker can submit a DSML add/modify request whose value is a URI to (1) perform server-side request forgery against i…

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
