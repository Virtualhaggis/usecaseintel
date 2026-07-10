# [CRIT] [GHSA / CRITICAL] GHSA-99j7-fhr2-xfj4: `exploration` was removed from crates.io for malicious code

**Source:** GitHub Security Advisories
**Published:** 2026-07-10
**Article:** https://github.com/advisories/GHSA-99j7-fhr2-xfj4

## Threat Profile

`exploration` was removed from crates.io for malicious code

A method within the `exploration` crate attempted to download and execute a payload from a remote site.

The malicious crate had 1 version published on 2026-06-02, approximately 1 hour before removal, and had no evidence of actual usage. This crate had no dependencies on crates.io.

Rustsec to Kirill Boychenko from the [Socket Threat Research Team](https://socket.dev/) for reporting this crate.

Affected packages: rust:exploration (vul…

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
