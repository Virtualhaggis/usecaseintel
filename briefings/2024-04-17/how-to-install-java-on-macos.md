# [MED] How to install Java on macOS

**Source:** Snyk
**Published:** 2024-04-17
**Article:** https://snyk.io/blog/install-java-on-macos/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
April 17, 2024
0 mins read What is Java? Java is a high-level, class-based, object-oriented programming language that was designed to have as few implementation dependencies as possible. It is a computing platform that was first introduced by Sun Microsystems in 1995. Many applications and websites today won't work unless you have Java installed, and more are created every day.
Java is well-known for its "Write Once, Run Anywhere" functionality. Th…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — How to install Java on macOS

`UC_1254_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — How to install Java on macOS ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/opt/homebrew/opt/openjdk*" OR Filesystem.file_path="*/usr/libexec/java_home*" OR Filesystem.file_path="*/Library/Java/JavaVirtualMachines/*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — How to install Java on macOS
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/opt/homebrew/opt/openjdk", "/usr/libexec/java_home", "/Library/Java/JavaVirtualMachines/"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
