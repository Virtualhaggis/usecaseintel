# [MED] Grok Build Uploads Entire Git Repositories to xAI Storage, Not Just Files It Reads

**Source:** The Hacker News
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/grok-build-uploads-entire-git.html

## Threat Profile

Grok Build Uploads Entire Git Repositories to xAI Storage, Not Just Files It Reads 
 Swati Khandelwal  Jul 14, 2026 Artificial Intelligence / Data Privacy 
xAI's Grok Build coding CLI was uploading entire Git repositories, full commit history and all, to a Google Cloud Storage bucket run by xAI, not just the files a coding task needed.
A researcher publishing as cereblab , testing version 0.2.93 , captured one of those uploads, cloned the git bundle out of the intercepted request, and pulled b…

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
