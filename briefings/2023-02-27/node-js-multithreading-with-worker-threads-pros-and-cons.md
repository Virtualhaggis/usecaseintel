# [MED] Node.js multithreading with worker threads: pros and cons

**Source:** Snyk
**Published:** 2023-02-27
**Article:** https://snyk.io/blog/node-js-multithreading-worker-threads-pros-cons/

## Threat Profile

Snyk Blog In this article
Written by James Walker 
February 27, 2023
0 mins read Node.js presents a single-threaded event loop to your application, which allows CPU-bound operations to block the main thread and create delays. The worker_threads module addresses this problem by providing a mechanism for running code in parallel using a form of threading.
In a previous post , you learned what worker threads are, their common use cases, and how to add them to your project. In this article, we'll lo…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Node.js multithreading with worker threads: pros and cons

`UC_1845_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Node.js multithreading with worker threads: pros and cons ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","shared.js","main.js","worker.js","bree-main.js","job.js","fixed-worker.js","dynamic-worker.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","shared.js","main.js","worker.js","bree-main.js","job.js","fixed-worker.js","dynamic-worker.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Node.js multithreading with worker threads: pros and cons
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "shared.js", "main.js", "worker.js", "bree-main.js", "job.js", "fixed-worker.js", "dynamic-worker.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "shared.js", "main.js", "worker.js", "bree-main.js", "job.js", "fixed-worker.js", "dynamic-worker.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
