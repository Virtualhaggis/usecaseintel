# [HIGH] Blackfield ransomware asks Nidec Corporation for $2 million ransom

**Source:** BleepingComputer
**Published:** 2026-06-30
**Article:** https://www.bleepingcomputer.com/news/security/blackfield-ransomware-asks-nidec-corporation-for-2-million-ransom/

## Threat Profile

Blackfield ransomware asks Nidec Corporation for $2 million ransom 
By Bill Toulas 
June 30, 2026
05:41 AM
0 
The Blackfield ransomware gang is asking for a $2 million ransom from Nidec Corporation, a large Japanese manufacturer of electronic components for automotive and computing applications.
Nidec is a leader in producing motors of all sizes, from micro-precision ones used in phones and hard drives to heavy-duty motors for robotics,  elevators, and large HVAC systems.
The company also design…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `ccic.com.tw`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1071** — Application Layer Protocol
- **T1490** — Inhibit System Recovery
- **T1047** — Windows Management Instrumentation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Blackfield (BlackFL) ransomware encryption: .BlackFL extension + BlackField_ReadMe.txt note drop

`UC_13_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path dc(Filesystem.file_path) as folder_count from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.BlackFL" OR Filesystem.file_name="BlackField_ReadMe.txt" OR Filesystem.file_name="BlackField-ReadMe.txt") by Filesystem.dest Filesystem.process_id Filesystem.action | `drop_dm_object_name(Filesystem)` | where count>=1 | convert ctime(firstTime) ctime(lastTime) | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName endswith ".BlackFL"
    or FileName matches regex @"(?i)BlackField[_-]ReadMe\.txt"
| summarize EncryptedFileCount = countif(FileName endswith ".BlackFL"),
            RansomNoteDropped = countif(FileName matches regex @"(?i)BlackField[_-]ReadMe\.txt"),
            AffectedFolders = dcount(FolderPath),
            SampleFiles = make_set(FileName, 8),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            InitiatingProcess = any(InitiatingProcessFileName),
            InitiatingProcessSHA256 = any(InitiatingProcessSHA256),
            InitiatingCmd = any(InitiatingProcessCommandLine)
        by DeviceName, InitiatingProcessId
| where EncryptedFileCount >= 1 or RansomNoteDropped >= 1
| order by FirstSeen desc
```

### Blackfield ransomware Volume Shadow Copy deletion via WMIC (inhibit recovery)

`UC_13_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where ((Processes.process_name="wmic.exe" AND Processes.process="*shadowcopy*" AND Processes.process="*delete*") OR (Processes.process_name="vssadmin.exe" AND Processes.process="*delete*" AND Processes.process="*shadows*")) by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | search user!="*$" | convert ctime(firstTime) ctime(lastTime) | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy" and ProcessCommandLine has "delete")
    or (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `ccic.com.tw`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
