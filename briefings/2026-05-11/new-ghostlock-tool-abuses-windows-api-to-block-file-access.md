# [HIGH] New GhostLock tool abuses Windows API to block file access

**Source:** BleepingComputer
**Published:** 2026-05-11
**Article:** https://www.bleepingcomputer.com/news/security/new-ghostlock-tool-abuses-windows-api-to-block-file-access/

## Threat Profile

New GhostLock tool abuses Windows API to block file access 
By Lawrence Abrams 
May 11, 2026
06:02 PM
0 
A security researcher has released a proof-of-concept tool named GhostLock that demonstrates how a legitimate Windows file API can be abused in attacks to block access to files stored locally or on SMB network shares.
This technique, created by Kim Dvash of Israel Aerospace Industries, abuses the Windows ' CreateFileW ' API and file-sharing modes to prevent other users and applications from o…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1499.001** — Endpoint Denial of Service: OS Exhaustion Flood
- **T1531** — Account Access Removal
- **T1135** — Network Share Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GhostLock SMB deny-share tool execution (Python script + distinctive CLI flags)

`UC_17_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where (Processes.process_name IN ("python.exe","pythonw.exe","py.exe") OR Processes.parent_process_name IN ("python.exe","pythonw.exe","py.exe")) AND (Processes.process="*ghostlock.py*" OR Processes.process="*--hold-indefinite*" OR Processes.process="*--confirm-existing-lock*" OR Processes.process="*--existing-folder*" OR Processes.process="*--targets-file*" OR Processes.process="*ghostlock_cache.json*") AND NOT Processes.user IN ("*$","SYSTEM","LOCAL SERVICE","NETWORK SERVICE") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName in~ ("python.exe","pythonw.exe","py.exe")
     or InitiatingProcessFileName in~ ("python.exe","pythonw.exe","py.exe"))
| where ProcessCommandLine has_any ("ghostlock.py","--hold-indefinite","--confirm-existing-lock","--existing-folder","--targets-file","ghostlock_cache.json",".ghostlock_authorized")
   or InitiatingProcessCommandLine has_any ("ghostlock.py","--hold-indefinite","--confirm-existing-lock","--existing-folder","--targets-file")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Single-user SMB share file-open fan-out indicating GhostLock-style mass deny-share

`UC_17_5` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`wineventlog_security` EventCode=5145
| rex field=_raw "Account Name:\s+(?<sub_account>[^\r\n]+)"
| rex field=_raw "Source Address:\s+(?<src_ip>[^\r\n]+)"
| rex field=_raw "Share Name:\s+(?<share_name>[^\r\n]+)"
| rex field=_raw "Relative Target Name:\s+(?<rel_target>[^\r\n]+)"
| eval account=coalesce(Account_Name, sub_account)
| where NOT match(account,"\$$") AND account!="ANONYMOUS LOGON" AND account!="SYSTEM"
| bin _time span=5m
| stats dc(rel_target) as FilesAccessed values(share_name) as shares values(src_ip) as src_ips min(_time) as firstTime max(_time) as lastTime by host account _time
| eval duration_sec=lastTime-firstTime, opens_per_sec=round(FilesAccessed/coalesce(duration_sec,1),2)
| where FilesAccessed > 500 AND opens_per_sec > 3
| sort - FilesAccessed
```

**Defender KQL:**
```kql
// Best-effort: Defender XDR cannot see pure read-only CreateFileW handles, but file servers with MDE may emit DeviceFileEvents for any incidental SMB activity. Primary detection lives in Sentinel via Event 5145.
let WindowMin = 5m;
let FileThreshold = 500;
DeviceFileEvents
| where Timestamp > ago(1d)
| where isnotempty(ShareName)
| where isnotempty(RequestAccountName)
| where RequestAccountName !endswith "$" and RequestAccountName !in~ ("SYSTEM","ANONYMOUS LOGON","LOCAL SERVICE","NETWORK SERVICE")
| summarize FilesTouched = dcount(strcat(FolderPath, "\\", FileName)),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SrcIPs = make_set(RequestSourceIP, 5),
            Shares = make_set(ShareName, 5),
            SampleFiles = make_set(FileName, 10)
            by DeviceName, RequestAccountName, RequestAccountDomain, bin(Timestamp, WindowMin)
| where FilesTouched > FileThreshold
| extend DurationSec = datetime_diff('second', LastSeen, FirstSeen)
| extend AccessPerSec = todouble(FilesTouched) / iif(DurationSec > 0, todouble(DurationSec), 1.0)
| where AccessPerSec > 3
| order by FilesTouched desc
```

### [LLM] GhostLock impact-report and authorisation-sentinel artifacts written to disk

`UC_17_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths values(Filesystem.process_name) as procs from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("lock_impact_result.json","lock_impact_result.md","ghostlock_cache.json",".ghostlock_authorized","ghostlock.py") OR Filesystem.file_path="*\\ghostlock\\*" OR Filesystem.file_path="*/ghostlock/*") AND NOT Filesystem.user IN ("*$","SYSTEM") by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName in~ ("lock_impact_result.json","lock_impact_result.md","ghostlock_cache.json",".ghostlock_authorized","ghostlock.py")
   or FolderPath contains "ghostlock"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessAccountDomain, SHA256
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
