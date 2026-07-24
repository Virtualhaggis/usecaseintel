# [CRIT] [GHSA / CRITICAL] GHSA-w4hw-qcx7-56pr: Shescape: Shell injection via unescaped parentheses on Windows with CMD

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-w4hw-qcx7-56pr

## Threat Profile

Shescape: Shell injection via unescaped parentheses on Windows with CMD

### Impact

This impacts users of Shescape on Windows that explicitly configure `shell` to CMD, or `true` with the default shell being CMD, using the `escape` and `escapeAll` APIs.

An attacker may be able to achieve shell injection depending on the original command.

```javascript
import * as cp from "node:child_process";
import { Shescape } from "shescape";

// 1. Prerequisites
const options = {
    shell: "cmd.exe",
    …

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
