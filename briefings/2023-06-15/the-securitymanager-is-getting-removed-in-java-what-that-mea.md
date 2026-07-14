# [HIGH] The SecurityManager is getting removed in Java: What that means for you

**Source:** Snyk
**Published:** 2023-06-15
**Article:** https://snyk.io/blog/securitymanager-removed-java/

## Threat Profile

Snyk Blog In this article
Written by Mdu Sibisi 
June 15, 2023
0 mins read The Java Development Kit (JDK) library's java.security package is one of the most important packages, yet despite consistent updates, it remains vastly underutilized .
In light of the increased emphasis on cybersecurity frameworks, including zero trust , it's imperative for Java developers to become familiar with Java SE's security libraries .
As with any other field in information technology, cybersecurity has a capricio…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — The SecurityManager is getting removed in Java: What that means for you

`UC_1660_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The SecurityManager is getting removed in Java: What that means for you ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/home/source/*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The SecurityManager is getting removed in Java: What that means for you
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/home/source/"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
