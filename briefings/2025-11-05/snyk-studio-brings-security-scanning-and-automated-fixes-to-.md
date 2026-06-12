# [LOW] Snyk Studio brings security scanning and automated fixes to Factory's Droids

**Source:** Snyk
**Published:** 2025-11-05
**Article:** https://snyk.io/blog/snyk-factory-partner-integration/

## Threat Profile

Snyk Blog In this article
Written by Sarah Conway 
November 5, 2025
0 mins read Snyk is thrilled to announce our partnership with Factory, which brings Snyk Studio directly into Droid workflows. 
AI agents, such as Factory’s Droids , can generate thousands of lines of code at incredible speed and are transforming modern software development. Yet every time a Factory Droid quickly ships a feature in minutes vs. days, refactors an entire module, and updates dependencies across a repo, it’s potenti…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Snyk Studio brings security scanning and automated fixes to Factory's Droids

`UC_713_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Snyk Studio brings security scanning and automated fixes to Factory's Droids ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/Application*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Snyk Studio brings security scanning and automated fixes to Factory's Droids
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/Application"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **LOW** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
