# [HIGH] Gunra Ransomware Expands RaaS Operations After Shifting From Conti-Based Locker

**Source:** Cyber Security News
**Published:** 2026-05-15
**Article:** https://cybersecuritynews.com/gunra-ransomware-expands-raas-operations/

## Threat Profile

Home Cyber Security News 
Gunra Ransomware Expands RaaS Operations After Shifting From Conti-Based Locker 
By Tushar Subhra Dutta 
May 15, 2026 
Gunra ransomware has quickly grown from a new threat into a serious global problem, hitting dozens of organizations in less than a year. 
The group behind it is not just encrypting data, but also running a business-like operation that sells access, leaks stolen files, and recruits partners to spread its malware. For defenders, this is not a one-off camp…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1485** — Data Destruction
- **T1490** — Inhibit System Recovery
- **T1047** — Windows Management Instrumentation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Gunra ransomware encryption artefacts — .ENCRT extension and R3ADM3.txt note drop

`UC_14_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_paths values(Filesystem.process_name) as process_names dc(Filesystem.file_name) as distinct_files from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_name="*.ENCRT" OR Filesystem.file_name="R3ADM3.txt" OR Filesystem.file_name="CONTI_LOG.txt") by Filesystem.dest Filesystem.user _time span=5m | `drop_dm_object_name(Filesystem)` | where distinct_files>=2 OR file_name="R3ADM3.txt" OR file_name="CONTI_LOG.txt" | sort - firstTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed")
| where FileName endswith ".ENCRT"
    or FileName =~ "R3ADM3.txt"
    or FileName =~ "CONTI_LOG.txt"
| summarize FileCount = count(),
            DistinctNames = dcount(FileName),
            EncryptedCount = countif(FileName endswith ".ENCRT"),
            NoteDropped = countif(FileName =~ "R3ADM3.txt"),
            ContiLogDropped = countif(FileName =~ "CONTI_LOG.txt"),
            SampleEncrypted = take_any(FileName),
            FolderPaths = make_set(FolderPath, 10),
            InitiatingProcess = take_any(InitiatingProcessFileName),
            InitiatingCmd = take_any(InitiatingProcessCommandLine),
            InitiatingSHA256 = take_any(InitiatingProcessSHA256)
    by DeviceId, DeviceName, bin(Timestamp, 5m)
| where NoteDropped > 0 or ContiLogDropped > 0 or EncryptedCount >= 5
| order by Timestamp desc
```

### [LLM] Gunra per-shadow-ID WMIC deletion — `WMIC shadowcopy where ID={GUID} delete` pattern

`UC_14_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as commands values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where Processes.process_name="wmic.exe" Processes.process="*shadowcopy*" Processes.process="*where*" Processes.process="*ID=*" Processes.process="*delete*" by Processes.dest Processes.user Processes.process_name _time span=5m | `drop_dm_object_name(Processes)` | where count>=2 | sort - firstTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has "shadowcopy"
    and ProcessCommandLine has "where"
    and ProcessCommandLine has "delete"
| where ProcessCommandLine matches regex @'(?i)shadowcopy\s+where\s+"?ID\s*=\s*\{[0-9A-Fa-f-]{30,}\}'
| where AccountName !endswith "$"
| summarize InvocationCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            DistinctGUIDs = dcount(ProcessCommandLine),
            SampleCmd = take_any(ProcessCommandLine),
            Parent = take_any(InitiatingProcessFileName),
            ParentCmd = take_any(InitiatingProcessCommandLine),
            GrandParent = take_any(InitiatingProcessParentFileName)
    by DeviceId, DeviceName, AccountName, bin(Timestamp, 10m)
| where InvocationCount >= 2 or DistinctGUIDs >= 2
| order by FirstSeen desc
```

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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

Severity classified as **HIGH** based on: 8 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
