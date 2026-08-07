# [HIGH] The dangers of assert in Python

**Source:** Snyk
**Published:** 2022-08-18
**Article:** https://snyk.io/blog/the-dangers-of-assert-in-python/

## Threat Profile

Snyk Blog In this article
Written by Dhruv Patel 
August 18, 2022
0 mins read There are many ways to find bugs in Python code: the built-in debugger ( pdb ), a healthy amount of unit tests , a debugger in an IDE like Pycharm or Visual Studio, try/catch statements, if/else statements, assert statements , or the tried and true practice of covering every inch of your codebase in print() statements like it’s going out of style.
Assert statements can help us catch bugs quickly and are far less intrus…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — The dangers of assert in Python

`UC_2079_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The dangers of assert in Python ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("safe_assert_example.py","example.py","unsafe_assert_example.py","nsafe_assert_example.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("safe_assert_example.py","example.py","unsafe_assert_example.py","nsafe_assert_example.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The dangers of assert in Python
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("safe_assert_example.py", "example.py", "unsafe_assert_example.py", "nsafe_assert_example.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("safe_assert_example.py", "example.py", "unsafe_assert_example.py", "nsafe_assert_example.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
