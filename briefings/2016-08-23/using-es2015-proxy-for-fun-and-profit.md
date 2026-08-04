# [MED] Using ES2015 Proxy for fun and profit

**Source:** Snyk
**Published:** 2016-08-23
**Article:** https://snyk.io/blog/using-es2015-proxy-for-fun-and-profit/

## Threat Profile

Snyk Blog Written by Alon Niv 
August 23, 2016
0 mins read Much has been written about ES2015 - with its arrow functions, scoped variable declarations and controversial classes. However, a certain feature has received little love so far: the Proxy .As JS developers, we’re not used to relying on trapping mechanisms throughout our codebase, but they have several very useful applications. To name a few:
Testing, mocking and monkeypatching
The Observer and Visitor design patterns
Abstractions over c…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Using ES2015 Proxy for fun and profit

`UC_3680_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Using ES2015 Proxy for fun and profit ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Using ES2015 Proxy for fun and profit
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
