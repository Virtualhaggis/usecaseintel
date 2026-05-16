# [CRIT] [GHSA / CRITICAL] GHSA-vj3m-2g9h-vm4p: Grav has multiple RCE vectors: unsafe unserialize (x3), command injection in git clone, SSTI blocklist bypass

**Source:** GitHub Security Advisories
**Published:** 2026-05-05
**Article:** https://github.com/advisories/GHSA-vj3m-2g9h-vm4p

## Threat Profile

Grav has multiple RCE vectors: unsafe unserialize (x3), command injection in git clone, SSTI blocklist bypass

Multiple RCE vectors were found in Grav CMS. Three are critical, two are high.

**1. Unsafe unserialize() in JobQueue — direct RCE gadget (Critical)**

`system/src/Grav/Common/Scheduler/JobQueue.php:465` calls `unserialize(base64_decode(...))` without restricting `allowed_classes`. The `Job` class has `call_user_func_array($this->command, $this->args)` in its execution path, which is a …

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
