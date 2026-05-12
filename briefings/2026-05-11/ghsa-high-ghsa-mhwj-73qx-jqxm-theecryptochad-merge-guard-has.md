# [MED] [GHSA / HIGH] GHSA-mhwj-73qx-jqxm: @theecryptochad/merge-guard has Prototype Pollution in its deepMerge() function

**Source:** GitHub Security Advisories
**Published:** 2026-05-11
**Article:** https://github.com/advisories/GHSA-mhwj-73qx-jqxm

## Threat Profile

@theecryptochad/merge-guard has Prototype Pollution in its deepMerge() function

## Summary

`@theecryptochad/merge-guard` versions prior to 1.0.1 are vulnerable to Prototype Pollution via the `deepMerge()` function. An attacker who controls the source object can inject `__proto__` keys that mutate `Object.prototype`, affecting all objects in the Node.js runtime.

## Details

The `deepMerge()` function recursively merges two objects without sanitizing reserved property keys (`__proto__`, `constr…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / HIGH] GHSA-mhwj-73qx-jqxm: @theecryptochad/merge-guard has Prototype Pol

`UC_71_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / HIGH] GHSA-mhwj-73qx-jqxm: @theecryptochad/merge-guard has Prototype Pol ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / HIGH] GHSA-mhwj-73qx-jqxm: @theecryptochad/merge-guard has Prototype Pol
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
