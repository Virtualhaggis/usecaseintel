# [CRIT] [GHSA / CRITICAL] GHSA-w4v6-g3wm-w36c: OpenClaw: QQBot admin commands could skip DM-only and allowFrom policy

**Source:** GitHub Security Advisories
**Published:** 2026-07-02
**Article:** https://github.com/advisories/GHSA-w4v6-g3wm-w36c

## Threat Profile

OpenClaw: QQBot admin commands could skip DM-only and allowFrom policy

### Summary

QQBot admin commands could skip DM-only and allowFrom policy. In affected versions, a QQBot sender able to trigger the exported command could route admin commands without the QQBot-specific DM-only and allowFrom checks.

This advisory is scoped to the named feature and configuration. It does not change OpenClaw's trusted-operator model: authenticated Gateway operators, installed plugins, and intentional local ex…

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
