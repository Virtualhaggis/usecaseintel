# [MED] 10 Dimensions of Python Static Analysis

**Source:** Snyk
**Published:** 2024-07-17
**Article:** https://snyk.io/blog/10-dimensions-of-python-static-analysis/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
July 17, 2024
0 mins read Python static analysis, also known as "linting", is a crucial aspect of software development. It involves inspecting your Python code without running it to identify potential bugs, programming errors, stylistic issues, or non-adhering patterns to predefined coding standards. It also helps identify vulnerabilities early in the development process, reducing the chances of deploying insecure code into production. For instance…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — 10 Dimensions of Python Static Analysis

`UC_1293_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — 10 Dimensions of Python Static Analysis ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("test.py","node.js","hello.py","example.py","your_file.py","app.py","your_python_file.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("test.py","node.js","hello.py","example.py","your_file.py","app.py","your_python_file.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — 10 Dimensions of Python Static Analysis
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("test.py", "node.js", "hello.py", "example.py", "your_file.py", "app.py", "your_python_file.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("test.py", "node.js", "hello.py", "example.py", "your_file.py", "app.py", "your_python_file.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
