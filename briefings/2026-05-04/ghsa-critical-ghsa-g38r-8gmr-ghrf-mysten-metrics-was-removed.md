# [CRIT] [GHSA / CRITICAL] GHSA-g38r-8gmr-ghrf: `mysten-metrics` was removed from crates.io for malicious code

**Source:** GitHub Security Advisories
**Published:** 2026-05-04
**Article:** https://github.com/advisories/GHSA-g38r-8gmr-ghrf

## Threat Profile

`sui-execution-cut` was removed from crates.io for malicious code

`sui-execution-cut` included a build script that attempted to exfiltrate data from the build machine.

The malicious crate had 1 version published on 2026-04-20 and had no evidence of actual usage. This crate had no dependencies on crates.io.

Affected packages: rust:sui-execution-cut (vuln >= 0).

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
