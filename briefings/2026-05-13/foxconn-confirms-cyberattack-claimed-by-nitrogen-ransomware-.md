# [HIGH] Foxconn confirms cyberattack claimed by Nitrogen ransomware gang

**Source:** BleepingComputer
**Published:** 2026-05-13
**Article:** https://www.bleepingcomputer.com/news/security/electronics-giant-foxconn-confirms-cyberattack-on-north-american-factories/

## Threat Profile

Foxconn confirms cyberattack claimed by Nitrogen ransomware gang 
By Sergiu Gatlan 
May 13, 2026
08:49 AM
0 


Foxconn, the world's largest electronics manufacturer, says some of its North American factories are now working to resume normal operations after a cyberattack.


The electronics giant has over 900,000 employees across over 240 campuses in 24 countries and reported revenues of over $260 billion in 2025. The company is ranked 28th in Fortune Global 500 and manufactures a wide range …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1574.002** — DLL Side-Loading
- **T1608.001** — Upload Malware
- **T1189** — Drive-by Compromise
- **T1068** — Exploitation for Privilege Escalation
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1014** — Rootkit
- **T1490** — Inhibit System Recovery
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
- **T1562.009** — Impair Defenses: Safe Mode Boot

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Nitrogen malvertising loader: trojanized IT-utility installer side-loading python312.dll

`UC_3_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Processes.process) as parent_cmd from datamodel=Endpoint.Filesystem where Filesystem.file_name="python312.dll" (Filesystem.file_path="*\\Users\\*\\Downloads\\*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*\\AppData\\Roaming\\*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search process_name IN ("WinSCP*.exe","AnyDesk*.exe","advanced_ip_scanner*.exe","anyconnect*.exe","putty*.exe","treesize*.exe","slack*.exe","Setup.exe","install.exe") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Nitrogen Stage-1 — python312.dll dropped/loaded by a trojanized utility installer in user-writable path
let TrojanizedSetups = dynamic(["winscp","anydesk","advanced_ip_scanner","advanced-ip-scanner","anyconnect","putty","treesize","slack","setup.exe","install.exe","installer.exe"]);
let KnownBadHashes = dynamic(["fa3eca4d53a1b7c4cfcd14f642ed5f8a8a864f56a8a47acbf5cf11a6c5d2afa2"]);
let FileDrops =
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileCreated"
    | where FileName =~ "python312.dll"
    | where FolderPath has_any (@"\Users\", @"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Downloads\", @"\Public\")
    | where not(FolderPath startswith @"C:\Program Files\" or FolderPath startswith @"C:\Program Files (x86)\" or FolderPath startswith @"C:\Windows\")
    | where InitiatingProcessFileName has_any (TrojanizedSetups) or SHA256 in~ (KnownBadHashes)
    | project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, SHA256,
              DroppingProcess = InitiatingProcessFileName,
              DroppingCmd = InitiatingProcessCommandLine;
let LibLoads =
    DeviceImageLoadEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "python312.dll"
    | where InitiatingProcessFileName has_any (TrojanizedSetups)
    | where not(FolderPath startswith @"C:\Program Files\" or FolderPath startswith @"C:\Program Files (x86)\" or FolderPath startswith @"C:\Python")
    | project Timestamp, DeviceName, FolderPath, SHA256,
              LoadingProcess = InitiatingProcessFileName,
              LoadingCmd = InitiatingProcessCommandLine;
union FileDrops, LibLoads
| order by Timestamp desc
```

### [LLM] Nitrogen BYOVD - truesight.sys (Adlice RogueKiller) driver load for EDR/AV termination

`UC_3_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_paths values(Filesystem.process_name) as droppers from datamodel=Endpoint.Filesystem where Filesystem.file_name="truesight.sys" (Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\Users\\*" OR Filesystem.file_path="*\\AppData\\*") by Filesystem.dest Filesystem.user Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | where NOT match(droppers, "(?i)RogueKiller|Adlice") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Nitrogen BYOVD — truesight.sys (Adlice) dropped or loaded outside legitimate Adlice/RogueKiller install path
let DropEvents =
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "truesight.sys"
    | where ActionType in ("FileCreated","FileRenamed","FileModified")
    | where not(FolderPath has_any (@"\Adlice\", @"\RogueKiller\", @"\Program Files\Adlice\", @"\Program Files (x86)\Adlice\"))
    | where InitiatingProcessFileName !in~ ("rogkill.exe","RogueKiller.exe","RogueKillerCMD.exe","adlice.exe","msiexec.exe")
    | project EventTime = Timestamp, DeviceName, ActionType, FolderPath, SHA256,
              DroppingProcess = InitiatingProcessFileName,
              DroppingCmd = InitiatingProcessCommandLine, EvidenceType = "FileDrop";
let LoadEvents =
    DeviceImageLoadEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "truesight.sys"
    | where not(FolderPath has_any (@"\Adlice\", @"\RogueKiller\"))
    | project EventTime = Timestamp, DeviceName, ActionType, FolderPath, SHA256,
              DroppingProcess = InitiatingProcessFileName,
              DroppingCmd = InitiatingProcessCommandLine, EvidenceType = "DriverLoad";
union DropEvents, LoadEvents
| order by EventTime desc
```

### [LLM] Nitrogen pre-encryption sequence: bcdedit safe-boot tamper + Windows event log clear within 1 hour

`UC_3_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as bcdedit_time values(Processes.process) as bcdedit_cmd from datamodel=Endpoint.Processes where Processes.process_name="bcdedit.exe" (Processes.process="*safeboot*" OR Processes.process="*recoveryenabled*no*" OR Processes.process="*bootstatuspolicy*ignoreallfailures*") by Processes.dest Processes.user | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats summariesonly=true min(_time) as clear_time values(Processes.process) as clear_cmd from datamodel=Endpoint.Processes where (Processes.process_name="wevtutil.exe" AND Processes.process="*cl*") OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*Clear-EventLog*" OR Processes.process="*ClearEventLog*")) by Processes.dest Processes.user | `drop_dm_object_name(Processes)`] | eval delta_sec=abs(clear_time-bcdedit_time) | where delta_sec<=3600 | table bcdedit_time clear_time delta_sec dest user bcdedit_cmd clear_cmd
```

**Defender KQL:**
```kql
// Nitrogen pre-encryption combo — bcdedit safeboot/recovery tamper + Security event-log clear on same host within 1h
let WindowMin = 60m;
let BcdEdit =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "bcdedit.exe"
    | where ProcessCommandLine has_any ("safeboot", "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "recoveryenabled No")
    | project BcdTime = Timestamp, DeviceId, DeviceName, AccountName,
              BcdCmd = ProcessCommandLine,
              BcdParent = InitiatingProcessFileName;
let LogClear =
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any (" cl ", " cl-l ", " clear-log "))
         or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Clear-EventLog", "ClearEventLog(", "Win32_NTEventlogFile"))
         or (FileName =~ "wmic.exe" and ProcessCommandLine has "nteventlog" and ProcessCommandLine has "cleareventlog")
    | project ClearTime = Timestamp, DeviceId,
              ClearCmd = ProcessCommandLine,
              ClearBinary = FileName;
BcdEdit
| join kind=inner LogClear on DeviceId
| where abs(datetime_diff('second', BcdTime, ClearTime)) <= 3600
| project DeviceName, AccountName, BcdTime, ClearTime,
          DeltaSec = datetime_diff('second', ClearTime, BcdTime),
          BcdCmd, ClearBinary, ClearCmd, BcdParent
| order by BcdTime desc
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


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
