# [CRIT] [GHSA / CRITICAL] GHSA-7f79-rvx6-vxc4: Duplicate Advisory: Picklescan does not block ctypes

**Source:** GitHub Security Advisories
**Published:** 2026-06-17
**Article:** https://github.com/advisories/GHSA-7f79-rvx6-vxc4

## Threat Profile

Duplicate Advisory: Picklescan does not block ctypes

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-4675-36f9-wf6r. This link is maintained to preserve external references.

### Original Description
picklescan before 0.0.33 fails to block the ctypes module, allowing attackers to achieve remote code execution by invoking direct syscalls and accessing raw memory. Attackers can craft malicious pickle files using ctypes.WinDLL to load kernel32.dll and exec…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-7f79-rvx6-vxc4: Duplicate Advisory: Picklescan does not b

`UC_58_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-7f79-rvx6-vxc4: Duplicate Advisory: Picklescan does not b ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("kernel32.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("kernel32.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-7f79-rvx6-vxc4: Duplicate Advisory: Picklescan does not b
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("kernel32.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("kernel32.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 1 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
