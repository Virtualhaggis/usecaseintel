# [MED] [GHSA / CRITICAL] GHSA-h29g-c9cx-c73q: torrentpier has PHP Serialize Injections

**Source:** GitHub Security Advisories
**Published:** 2026-05-11
**Article:** https://github.com/advisories/GHSA-h29g-c9cx-c73q

## Threat Profile

torrentpier has PHP Serialize Injections

### Summary
Hi, there. We've found PHP Serialize Injections in your project “torrentpier". According to the OWASP, it can pose a significant risk: enable an attacker to modify serialized objects in order to inject malicious data into the application code, resulting in code execution or an arbitrary reading of the file on any vulnerable system. 
                                        
### Details
In the attachment you can find a report with the number of…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- _Narrative-keyword inference returned no technique mappings; review article for ATT&CK relevance manually._

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

_No actionable hunts can be derived from the RSS summary alone. The article may still warrant manual review — open the source link for actor attribution, IOCs in the body, and TTP detail._


## Why this matters

Severity classified as **MED** based on: 0 use case(s) fired, 0 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
