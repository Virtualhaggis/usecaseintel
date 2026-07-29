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
- **T1565.001** — Data Manipulation: Stored Data Manipulation
- **T1070.004** — Indicator Removal: File Deletion
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vitest Browser Mode node.exe writes/deletes PNG or trace archive outside project into system paths

`UC_127_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name="node.exe" AND Filesystem.action IN ("created","modified","deleted") AND (Filesystem.file_path="*\\Windows\\*" OR Filesystem.file_path="*\\System32\\*" OR Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\Users\\Public\\*" OR Filesystem.file_path="*\\Programs\\Startup\\*") by Filesystem.dest Filesystem.process_name Filesystem.file_path Filesystem.file_name Filesystem.action
| `drop_dm_object_name(Filesystem)`
| where match(file_name,"(?i)\.(png|zip)$") OR action="deleted"
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has_any ("vitest","@vitest/browser")
| where ActionType in ("FileCreated","FileModified","FileDeleted","FileRenamed")
| where FolderPath has_any (@"\Windows\", @"\System32\", @"\ProgramData\", @"\Users\Public\", @"\Programs\Startup\")
| where (FileName endswith ".png" or FileName endswith ".zip" or ActionType == "FileDeleted")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName, InitiatingProcessCommandLine, InitiatingProcessId
| order by Timestamp desc
```

### Vitest Browser Mode / test API (node.exe) accepting inbound connections on 63315/51204 from non-loopback host

`UC_127_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="node.exe" AND All_Traffic.direction="inbound" AND All_Traffic.dest_port IN (63315,51204) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| where NOT cidrmatch("127.0.0.0/8",src) AND NOT cidrmatch("::1/128",src)
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (63315, 51204) or InitiatingProcessCommandLine has_any ("--browser.api","--api","test.api","vitest")
| where RemoteIPType == "Public" or (RemoteIP !in ("127.0.0.1","::1") and RemoteIPType != "Loopback")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, LocalPort, RemoteIP, RemoteIPType, RemotePort, InitiatingProcessId
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-p63j-vcc4-9vmv: @vitest/browser: Browser Mode provider co

`UC_127_0` · phase: **exploit** · confidence: **High**

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
