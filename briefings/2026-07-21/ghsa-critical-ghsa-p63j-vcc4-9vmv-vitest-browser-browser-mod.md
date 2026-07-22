# [CRIT] [GHSA / CRITICAL] GHSA-p63j-vcc4-9vmv: @vitest/browser: Browser Mode provider commands bypass the file-access permission gate

**Source:** GitHub Security Advisories
**Published:** 2026-07-21
**Article:** https://github.com/advisories/GHSA-p63j-vcc4-9vmv

## Threat Profile

@vitest/browser: Browser Mode provider commands bypass the file-access permission gate

## Summary

Browser Mode exposes a set of built-in "commands" that run on the Node.js side of the test runner and can touch the local filesystem (taking screenshots, managing Playwright traces, uploading files for `<input type="file">`, comparing screenshots).

Several of these commands accept a file path from the browser and act on it without checking the `allowWrite` permission gate and without confining th…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1565.001** — Data Manipulation: Stored Data Manipulation
- **T1485** — Data Destruction

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### @vitest/browser Browser Mode API exposed to non-loopback network (inbound to node/vitest)

`UC_9_1` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="node.exe" All_Traffic.direction="inbound" All_Traffic.src_category!="loopback" by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where src_ip!="127.0.0.1" AND src_ip!="::1"
| `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has "vitest"
| where ActionType == "InboundConnectionAccepted"
| where RemoteIPType == "Public" or (RemoteIP !startswith "127." and RemoteIP != "::1" and RemoteIP != "::")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, RemoteIP, RemotePort, LocalPort
| order by Timestamp desc
```

### Vitest Browser Mode provider command writes/deletes files outside project (node.exe PNG/zip to sensitive paths)

`UC_9_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name="node.exe" (Filesystem.action="created" OR Filesystem.action="deleted" OR Filesystem.action="modified") (Filesystem.file_path="*\\Windows\\*" OR Filesystem.file_path="*\\Startup\\*" OR Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\System32\\*" OR Filesystem.file_path="*\\Users\\Public\\*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `ctime(firstTime)` | `ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has "vitest"
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileDeleted")
| where (FileName endswith ".png" or FileName endswith ".zip" or ActionType == "FileDeleted")
| where FolderPath has_any (@"\Windows\", @"\System32\", @"\ProgramData\", @"\Users\Public\", @"\Start Menu\Programs\Startup", @"\Users\Administrator\")
   or FolderPath matches regex @"(?i)^[a-z]:\\[^\\]+\.(png|zip)$"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-p63j-vcc4-9vmv: @vitest/browser: Browser Mode provider co

`UC_9_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-p63j-vcc4-9vmv: @vitest/browser: Browser Mode provider co ```
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
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-p63j-vcc4-9vmv: @vitest/browser: Browser Mode provider co
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

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
