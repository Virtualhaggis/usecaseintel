# [MED] Snyk VulnBench JS 1.0: Can LLMs Find the Same Bugs Twice?

**Source:** Snyk
**Published:** 2026-06-29
**Article:** https://snyk.io/blog/snyk-vulnbench-js-1-0-llm-security-review-repeatability/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
June 29, 2026
0 mins read We ran 300 vulnerability-finding scans to measure how repeatable an agentic LLM security review is on the same code, prompt, and harness. The headline result is not that one scanner "wins" a self-referential leaderboard. It is that LLM security findings are unevenly repeatable: reference-matched findings were stable, but extra-model reports varied widely from run to run.
In plain terms, when Claude reported bugs outside th…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — Snyk VulnBench JS 1.0: Can LLMs Find the Same Bugs Twice?

`UC_164_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Snyk VulnBench JS 1.0: Can LLMs Find the Same Bugs Twice? ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("server.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/var/app/public/*" OR Filesystem.file_name IN ("server.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Snyk VulnBench JS 1.0: Can LLMs Find the Same Bugs Twice?
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("server.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/var/app/public/") or FileName in~ ("server.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
