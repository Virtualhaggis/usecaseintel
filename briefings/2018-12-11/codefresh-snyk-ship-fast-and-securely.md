# [HIGH] Codefresh + Snyk = ship fast and securely

**Source:** Snyk
**Published:** 2018-12-11
**Article:** https://snyk.io/blog/codefresh-snyk-ship-fast-and-securely/

## Threat Profile

Snyk Blog Written by Antoine Arlaud 
December 11, 2018
0 mins read Modern software development is about writing code. Not building, not shipping, but developing — we code, we merge, it builds, it ships. It’s important to test on both sides of the repo frontier, between the code and the automated part. The goal is to test before we merge so the changes go through the pipeline smoothly.
Pipelines are not meant for us developers to test our changes for the first time, it's meant to gate if our code…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Codefresh + Snyk = ship fast and securely

`UC_3280_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Codefresh + Snyk = ship fast and securely ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("snyk-cli.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/run/docker.sock*" OR Filesystem.file_path="*/var/lib/docker*" OR Filesystem.file_path="*/tmp/node_modules*" OR Filesystem.file_name IN ("snyk-cli.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Codefresh + Snyk = ship fast and securely
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("snyk-cli.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/run/docker.sock", "/var/lib/docker", "/tmp/node_modules") or FileName in~ ("snyk-cli.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
