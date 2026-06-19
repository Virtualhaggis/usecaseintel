# [HIGH] A tale of two eras

**Source:** Cisco Talos
**Published:** 2026-06-11
**Article:** https://blog.talosintelligence.com/a-tale-of-two-eras/

## Threat Profile

A tale of two eras 
By 
Amy Ciminnisi 
Thursday, June 11, 2026 14:00
Threat Source newsletter
Welcome to this week’s edition of the Threat Source newsletter. 
To the surprise of absolutely no one who has seen my face, I’m one of the younger employees at Talos. As my industry veteran colleagues were buying the first iPods, navigating the switch from dial-up to broadband, saying goodbye to floppy disks, and making Myspace accounts, I was playing with my  Password Journal and Friend Chips . It’s a …

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`
- **SHA256:** `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`
- **SHA256:** `a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91`
- **SHA256:** `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`
- **MD5:** `2915b3f8b703eb744fc54c81f4a9c67f`
- **MD5:** `aac3165ece2959f39ff98334618d10d9`
- **MD5:** `7bdbd180c081fa63ca94f9c22c457376`
- **MD5:** `38de5b216c33833af710e88f7f64fc98`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1496** — Resource Hijacking
- **T1055** — Process Injection
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Talos weekly prevalent malware hash execution (Coinminer/Injector/Dropper.Miner)

`UC_142_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_hash IN ("9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974","a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91","9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f","2915b3f8b703eb744fc54c81f4a9c67f","aac3165ece2959f39ff98334618d10d9","7bdbd180c081fa63ca94f9c22c457376","38de5b216c33833af710e88f7f64fc98")) by Processes.dest Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TalosSHA256 = dynamic(["9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974","a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91","9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f"]);
let TalosMD5 = dynamic(["2915b3f8b703eb744fc54c81f4a9c67f","aac3165ece2959f39ff98334618d10d9","7bdbd180c081fa63ca94f9c22c457376","38de5b216c33833af710e88f7f64fc98"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where SHA256 in (TalosSHA256) or MD5 in (TalosMD5) or InitiatingProcessSHA256 in (TalosSHA256) or InitiatingProcessMD5 in (TalosMD5)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, MD5, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### Talos prevalent malware hash dropped to disk (DeviceFileEvents pivot)

`UC_142_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.file_path) as path values(Filesystem.process_name) as dropper from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974","a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91","9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f","2915b3f8b703eb744fc54c81f4a9c67f","aac3165ece2959f39ff98334618d10d9","7bdbd180c081fa63ca94f9c22c457376","38de5b216c33833af710e88f7f64fc98")) by Filesystem.dest Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TalosSHA256 = dynamic(["9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507","96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974","a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91","9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f"]);
let TalosMD5 = dynamic(["2915b3f8b703eb744fc54c81f4a9c67f","aac3165ece2959f39ff98334618d10d9","7bdbd180c081fa63ca94f9c22c457376","38de5b216c33833af710e88f7f64fc98"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where SHA256 in (TalosSHA256) or MD5 in (TalosMD5)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5, FileOriginUrl, FileOriginIP, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Talos prevalent malware filename pattern — VID001.exe and d4aa3e70..._N_Exe.exe

`UC_142_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.parent_process_name) as parent values(Processes.process) as cmdline from datamodel=Endpoint.Processes where (Processes.process_name="VID001.exe" OR match(Processes.process_name, "^d4aa3e7010220ad1b458fac17039c274_\d+_Exe\.exe$")) Processes.process_path IN ("*\\Users\\*", "*\\AppData\\*", "*\\Temp\\*", "*\\Public\\*", "*\\ProgramData\\*") by Processes.dest Processes.process_name Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
( DeviceProcessEvents
  | where Timestamp > ago(14d)
  | where FileName =~ "VID001.exe" or FileName matches regex @"(?i)^d4aa3e7010220ad1b458fac17039c274_\d+_Exe\.exe$"
  | where FolderPath has_any (@"\Users\", @"\AppData\", @"\Temp\", @"\Public\", @"\ProgramData\")
  | project Timestamp, EventKind="ProcessExec", DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
),
( DeviceFileEvents
  | where Timestamp > ago(14d)
  | where ActionType in ("FileCreated","FileRenamed")
  | where FileName =~ "VID001.exe" or FileName matches regex @"(?i)^d4aa3e7010220ad1b458fac17039c274_\d+_Exe\.exe$"
  | project Timestamp, EventKind="FileDrop", DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine="", InitiatingProcessFileName, InitiatingProcessCommandLine
)
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

### Article-specific behavioural hunt — A tale of two eras

`UC_142_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — A tale of two eras ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("vid001.exe","d4aa3e7010220ad1b458fac17039c274_63_exe.exe","d4aa3e7010220ad1b458fac17039c274_62_exe.exe","sample.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("vid001.exe","d4aa3e7010220ad1b458fac17039c274_63_exe.exe","d4aa3e7010220ad1b458fac17039c274_62_exe.exe","sample.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — A tale of two eras
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("vid001.exe", "d4aa3e7010220ad1b458fac17039c274_63_exe.exe", "d4aa3e7010220ad1b458fac17039c274_62_exe.exe", "sample.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("vid001.exe", "d4aa3e7010220ad1b458fac17039c274_63_exe.exe", "d4aa3e7010220ad1b458fac17039c274_62_exe.exe", "sample.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9f1f11a708d393e0a4109ae189bc64f1f3e312653dcf317a2bd406f18ffcc507`, `96fa6a7714670823c83099ea01d24d6d3ae8fef027f01a4ddac14f123b1c9974`, `a31f222fc283227f5e7988d1ad9c0aecd66d58bb7b4d8518ae23e110308dbf91`, `9896a6fcb9bb5ac1ec5297b4a65be3f647589adf7c37b45f3f7466decd6a4a7f`, `2915b3f8b703eb744fc54c81f4a9c67f`, `aac3165ece2959f39ff98334618d10d9`, `7bdbd180c081fa63ca94f9c22c457376`, `38de5b216c33833af710e88f7f64fc98`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
