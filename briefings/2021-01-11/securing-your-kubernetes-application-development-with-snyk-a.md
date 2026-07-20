# [HIGH] Securing your Kubernetes application development with Snyk and Tilt

**Source:** Snyk
**Published:** 2021-01-11
**Article:** https://snyk.io/blog/securing-kubernetes-application-development-with-snyk-and-tilt/

## Threat Profile

Snyk Blog In this article
Written by Matt Jarvis 
January 11, 2021
0 mins read Developing Kubernetes applications can be hard. We’re often dealing with microservice architectures with a lot of moving parts, along with developing the cluster configuration to hook them all together, and workflows for rapid iteration and testing can become convoluted and hard to manage for engineering teams.
This is where tools like Tilt come in.
What is Tilt? Tilt is an awesome tool for developers working with Kub…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Securing your Kubernetes application development with Snyk and Tilt

`UC_3210_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Securing your Kubernetes application development with Snyk and Tilt ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","now.py","index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/local/bin/entr*" OR Filesystem.file_path="*/tmp/ref.txt*" OR Filesystem.file_name IN ("node.js","now.py","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Securing your Kubernetes application development with Snyk and Tilt
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "now.py", "index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/local/bin/entr", "/tmp/ref.txt") or FileName in~ ("node.js", "now.py", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
