# [MED] Fastify plugins as building blocks for a backend Node.js API

**Source:** Snyk
**Published:** 2024-05-28
**Article:** https://snyk.io/blog/fastify-plugins-for-backend-node-js-api/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
May 28, 2024
0 mins read In the world of building backend Node.js APIs, Fastify stands out with its plugin ecosystem and architecture approach, offering a compelling option beyond the conventional Express framework. This highly efficient, low-overhead web framework distinguishes itself through its remarkable speed and streamlined simplicity. At the heart of Fastify's design is a robust plugin architecture that leverages the asynchronous capabilitie…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Fastify plugins as building blocks for a backend Node.js API

`UC_1204_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Fastify plugins as building blocks for a backend Node.js API ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","plugin.js","server.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","plugin.js","server.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Fastify plugins as building blocks for a backend Node.js API
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "plugin.js", "server.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "plugin.js", "server.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
