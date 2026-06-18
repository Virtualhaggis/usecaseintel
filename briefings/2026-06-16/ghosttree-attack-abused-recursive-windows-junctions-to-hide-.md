# [HIGH] GhostTree Attack Abused Recursive Windows Junctions to Hide Malware

**Source:** BleepingComputer
**Published:** 2026-06-16
**Article:** https://www.bleepingcomputer.com/news/security/ghosttree-attack-abused-recursive-windows-junctions-to-hide-malware/

## Threat Profile

GhostTree Attack Abused Recursive Windows Junctions to Hide Malware 
Sponsored by Varonis 
June 16, 2026
10:17 AM
0 
Most security teams think of NTFS junctions and symbolic links as niche file system features. They let one directory point to another, like a shortcut that the OS treats as real. They exist for backward compatibility, storage management, things that rarely come up in a SOC. But they have a property that makes them interesting from an offensive perspective: any user can create them…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.002** — User Execution: Malicious File
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1027** — Obfuscated Files or Information
- **T1218** — System Binary Proxy Execution
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NTFS junction creation via cmd.exe mklink /J

`UC_52_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="cmd.exe" Processes.process="*mklink*" Processes.process="* /J *" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has "mklink" and ProcessCommandLine has "/J"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### NTFS reparse point manipulation via fsutil reparsepoint

`UC_52_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) as firstTime, max(_time) as lastTime, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="fsutil.exe" Processes.process="*reparsepoint*" (Processes.process="*create*" OR Processes.process="*set*") by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "fsutil.exe"
| where ProcessCommandLine has "reparsepoint"
| where ProcessCommandLine has_any ("create", "set")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### GhostTree pattern: multiple NTFS junctions created under same parent within minutes

`UC_52_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as JunctionCount, min(_time) as firstTime, max(_time) as lastTime, values(Processes.process) as SampleCmds from datamodel=Endpoint.Processes where Processes.process_name="cmd.exe" Processes.process="*mklink*" Processes.process="* /J *" by Processes.dest Processes.user _time span=10m | `drop_dm_object_name(Processes)` | where JunctionCount >= 2 | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where AccountName !endswith "$"
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has "mklink" and ProcessCommandLine has "/J"
| summarize JunctionCount = count(),
            SampleCmd = any(ProcessCommandLine),
            ParentProc = any(InitiatingProcessFileName),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
          by DeviceName, AccountName, bin(Timestamp, 10m)
| where JunctionCount >= 2
| order by LastSeen desc
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Article-specific behavioural hunt — GhostTree Attack Abused Recursive Windows Junctions to Hide Malware

`UC_52_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — GhostTree Attack Abused Recursive Windows Junctions to Hide Malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("program.exe") OR Processes.process_path="*C:\Parent\program.exe*" OR Processes.process_path="*C:\Parent\Child*" OR Processes.process_path="*C:\Parent\Child\Program.exe*" OR Processes.process_path="*C:\Parent\Child\Child\Program.exe*" OR Processes.process_path="*C:\Parent\Child\Child\Child\Child\Program.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Parent\program.exe*" OR Filesystem.file_path="*C:\Parent\Child*" OR Filesystem.file_path="*C:\Parent\Child\Program.exe*" OR Filesystem.file_path="*C:\Parent\Child\Child\Program.exe*" OR Filesystem.file_path="*C:\Parent\Child\Child\Child\Child\Program.exe*" OR Filesystem.file_path="*C:\Parent\Child1*" OR Filesystem.file_path="*C:\Parent\Child2*" OR Filesystem.file_path="*C:\Parent\Child1\Program.exe*" OR Filesystem.file_name IN ("program.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — GhostTree Attack Abused Recursive Windows Junctions to Hide Malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("program.exe") or FolderPath has_any ("C:\Parent\program.exe", "C:\Parent\Child", "C:\Parent\Child\Program.exe", "C:\Parent\Child\Child\Program.exe", "C:\Parent\Child\Child\Child\Child\Program.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Parent\program.exe", "C:\Parent\Child", "C:\Parent\Child\Program.exe", "C:\Parent\Child\Child\Program.exe", "C:\Parent\Child\Child\Child\Child\Program.exe", "C:\Parent\Child1", "C:\Parent\Child2", "C:\Parent\Child1\Program.exe") or FileName in~ ("program.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
