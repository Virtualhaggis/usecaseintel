# [HIGH] New Prinz Eugen ransomware prioritizes recent files for encryption

**Source:** BleepingComputer
**Published:** 2026-06-20
**Article:** https://www.bleepingcomputer.com/news/security/new-prinz-eugen-ransomware-prioritizes-recent-files-for-encryption/

## Threat Profile

New Prinz Eugen ransomware prioritizes recent files for encryption 
By Bill Toulas 
June 20, 2026
11:23 AM
0 
A new ransomware operation named ‘Prinz Eugen’ prioritizes recently modified files for encryption and leaves no ransom note on the system.
An investigation from Threatdown, Malwarebytes’ enterprise cybersecurity arm, found that the Prinz Eugen hackers have a hands-on-keyboard style and prefer to use legitimate remote monitoring and management (RMM) software and living-off-the-land tools.…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `stndrdbnk.cc`
- **Domain (defanged):** `6cudc5cqa2bjpwdhcwm2lj6dbqejjjqzeo6ipwvmbazr6cgu7vfk3dad.onion`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1485** — Data Destruction
- **T1133** — External Remote Services
- **T1136.001** — Create Account: Local Account
- **T1098** — Account Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Prinz Eugen ransomware payload 'servertool.exe' execution with --delete flag

`UC_6_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="servertool.exe" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| eval delete_flag=if(match(process,"(?i)--delete"),"yes","no")
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "servertool.exe"
| extend DeleteFlag = iff(ProcessCommandLine has "--delete", "yes", "no")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, DeleteFlag, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Prinz Eugen mass file encryption — .prinzeugen extension burst

`UC_6_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count dc(Filesystem.file_path) as distinct_files values(Filesystem.file_path) as sample_paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.prinzeugen" by Filesystem.dest Filesystem.process_id _time span=5m
| `drop_dm_object_name(Filesystem)`
| where distinct_files > 50
| sort - distinct_files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName endswith ".prinzeugen"
| summarize EncryptedFiles = dcount(FolderPath), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleProc = any(InitiatingProcessFileName), SampleCmd = any(InitiatingProcessCommandLine) by DeviceName, DeviceId, bin(Timestamp, 5m)
| where EncryptedFiles > 50   // 50 = burst floor; legit single .prinzeugen filenames are vanishingly rare
| order by EncryptedFiles desc
```

### RemotePC RMM tool deployment as Prinz Eugen post-compromise foothold

`UC_6_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="*remotepc*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where FileName has "remotepc" or InitiatingProcessFileName has "remotepc" or ProcessCommandLine has "remotepc"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Backdoor local administrator account creation (Prinz Eugen persistence)

`UC_6_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.object_category=user AND (All_Changes.action=created OR All_Changes.action=modified) by All_Changes.dest All_Changes.user All_Changes.object All_Changes.action
| `drop_dm_object_name(Change)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType in ("UserAccountCreated","UserAccountAddedToLocalGroup")
| extend GroupName = tostring(parse_json(AdditionalFields).GroupName)
| where ActionType == "UserAccountCreated" or GroupName has_any ("Administrators","Remote Desktop Users")
| project Timestamp, DeviceName, ActionType, AccountName, TargetAccount = tostring(parse_json(AdditionalFields).AccountName), GroupName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — New Prinz Eugen ransomware prioritizes recent files for encryption

`UC_6_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Prinz Eugen ransomware prioritizes recent files for encryption ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("servertool.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("servertool.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Prinz Eugen ransomware prioritizes recent files for encryption
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("servertool.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("servertool.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `stndrdbnk.cc`, `6cudc5cqa2bjpwdhcwm2lj6dbqejjjqzeo6ipwvmbazr6cgu7vfk3dad.onion`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
