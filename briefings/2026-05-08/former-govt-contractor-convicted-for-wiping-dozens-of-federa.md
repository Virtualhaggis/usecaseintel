# [HIGH] Former govt contractor convicted for wiping dozens of federal databases

**Source:** BleepingComputer
**Published:** 2026-05-08
**Article:** https://www.bleepingcomputer.com/news/security/former-govt-contractor-convicted-for-wiping-dozens-of-federal-databases/

## Threat Profile

Former govt contractor convicted for wiping dozens of federal databases 
By Sergiu Gatlan 
May 8, 2026
04:45 AM
0 
A 34-year-old Virginia man was found guilty of conspiring to destroy dozens of government databases after getting fired from his job as a federal contractor.
In 2016, Sohaib Akhter and his twin brother and co-defendant Muneeb Akhter were also sentenced to several years in prison after pleading guilty to accessing U.S. State Department systems without authorization and stealing the p…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1485** — Data Destruction
- **T1565.001** — Stored Data Manipulation
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
- **T1070.004** — Indicator Removal: File Deletion
- **T1561.001** — Disk Content Wipe

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Mass database/document file deletion burst by single user account

`UC_32_0` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as file_count, dc(Filesystem.file_path) as distinct_files, values(Filesystem.file_name) as file_names, values(Filesystem.file_path) as file_paths, values(Filesystem.process_name) as processes, min(_time) as first_delete, max(_time) as last_delete from datamodel=Endpoint.Filesystem where Filesystem.action=deleted (Filesystem.file_name="*.mdf" OR Filesystem.file_name="*.ldf" OR Filesystem.file_name="*.ndf" OR Filesystem.file_name="*.bak" OR Filesystem.file_name="*.trn" OR Filesystem.file_name="*.mdb" OR Filesystem.file_name="*.accdb" OR Filesystem.file_name="*.sql" OR Filesystem.file_name="*.sqlite" OR Filesystem.file_name="*.db" OR Filesystem.file_name="*.dbf" OR Filesystem.file_name="*.bacpac" OR Filesystem.file_name="*.dacpac" OR Filesystem.file_name="*.dump") AND NOT (Filesystem.user="*$" OR Filesystem.user="SYSTEM" OR Filesystem.user="LOCAL SERVICE" OR Filesystem.user="NETWORK SERVICE") by Filesystem.dest, Filesystem.user, _time span=1h | `drop_dm_object_name(Filesystem)` | where distinct_files >= 25 | sort - distinct_files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileDeleted"
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessAccountName !in~ ("system","local service","network service")
| where FileName endswith ".mdf" or FileName endswith ".ldf" or FileName endswith ".ndf"
    or FileName endswith ".bak" or FileName endswith ".trn"
    or FileName endswith ".mdb" or FileName endswith ".accdb"
    or FileName endswith ".sql" or FileName endswith ".sqlite" or FileName endswith ".db"
    or FileName endswith ".dbf" or FileName endswith ".bacpac" or FileName endswith ".dacpac"
    or FileName endswith ".dump"
| summarize FilesDeleted = count(),
            DistinctFiles = dcount(strcat(FolderPath, FileName)),
            FirstDelete = min(Timestamp),
            LastDelete = max(Timestamp),
            SampleFiles = make_set(FileName, 25),
            Folders = make_set(FolderPath, 15),
            Processes = make_set(InitiatingProcessFileName, 10)
            by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1h)
| where DistinctFiles >= 25     // 25 = empirical mass-deletion floor; the Akhter case wiped ~96 in several hours
| order by DistinctFiles desc
```

### [LLM] Windows event log / USN journal clearing on user endpoint (anti-forensics)

`UC_32_1` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent, min(_time) as first_seen, max(_time) as last_seen from datamodel=Endpoint.Processes where (Processes.process_name="wevtutil.exe" AND (Processes.process="* cl *" OR Processes.process="* clear-log *" OR Processes.process="*/cl *")) OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*Clear-EventLog*" OR Processes.process="*Remove-EventLog*" OR Processes.process="*wevtutil*cl *" OR Processes.process="*Limit-EventLog*-Retention*")) OR (Processes.process_name="fsutil.exe" AND Processes.process="*usn deletejournal*") OR (Processes.process_name="WMIC.exe" AND Processes.process="*NTEVENTLOG*Cleareventlog*") AND NOT (Processes.user="*$" OR Processes.user="SYSTEM") by Processes.dest, Processes.user, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - last_seen
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any (" cl "," clear-log ","/cl "))
    or (FileName in~ ("powershell.exe","pwsh.exe")
        and ProcessCommandLine has_any ("Clear-EventLog","Remove-EventLog","wevtutil cl ","wevtutil clear-log","Limit-EventLog -Retention"))
    or (FileName =~ "fsutil.exe" and ProcessCommandLine has "usn deletejournal")
    or (FileName =~ "wmic.exe" and ProcessCommandLine has "NTEVENTLOG" and ProcessCommandLine has "Cleareventlog")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          IsRemoteSession = InitiatingProcessTokenElevation
| order by Timestamp desc
```

### [LLM] Pre-return endpoint wipe: cipher /w, sdelete, format, diskpart clean on a user laptop

`UC_32_2` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent, min(_time) as first_seen, max(_time) as last_seen from datamodel=Endpoint.Processes where ((Processes.process_name="cipher.exe" AND Processes.process="*/w*") OR (Processes.process_name IN ("sdelete.exe","sdelete64.exe")) OR (Processes.process_name="format.com" AND (Processes.process="* /p:*" OR Processes.process="*/p:*")) OR (Processes.process_name="diskpart.exe" AND Processes.process="*clean*") OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*Format-Volume*" OR Processes.process="*Clear-Disk*" OR Processes.process="*Initialize-Disk -PartitionStyle*")) OR (Processes.process_name="manage-bde.exe" AND Processes.process="*-forcerecovery*")) AND NOT (Processes.user="*$" OR Processes.user="SYSTEM") by Processes.dest, Processes.user, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | sort - last_seen
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
| where (FileName =~ "cipher.exe" and ProcessCommandLine has "/w")
    or (FileName in~ ("sdelete.exe","sdelete64.exe"))
    or (FileName =~ "format.com" and ProcessCommandLine has_any (" /p:","/p:"))
    or (FileName =~ "diskpart.exe" and ProcessCommandLine has "clean")
    or (FileName in~ ("powershell.exe","pwsh.exe")
        and ProcessCommandLine has_any ("Format-Volume","Clear-Disk","Initialize-Disk -PartitionStyle"))
    or (FileName =~ "manage-bde.exe" and ProcessCommandLine has "-forcerecovery")
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          ParentImage = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
