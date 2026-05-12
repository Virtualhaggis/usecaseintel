# [LOW] [GHSA / HIGH] GHSA-w94c-4vhp-22gx: @vitejs/plugin-rsc has a Denial of Service Vulnerability in React Server Components

**Source:** GitHub Security Advisories
**Published:** 2026-05-11
**Article:** https://github.com/advisories/GHSA-w94c-4vhp-22gx

## Threat Profile

@vitejs/plugin-rsc has a Denial of Service Vulnerability in React Server Components

### Impact

`@vitejs/plugin-rsc` vendors `react-server-dom-webpack`, which contained a vulnerability in versions prior to 19.2.6. See details in React repository's advisory https://github.com/facebook/react/security/advisories/GHSA-rv78-f8rc-xrxh

### Patches

Upgrade immediately to `@vitejs/plugin-rsc@0.5.26` or later.

Affected packages: npm:@vitejs/plugin-rsc (vuln <= 0.5.25).

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
