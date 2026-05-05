# [HIGH] HybridPetya: The Petya/NotPetya copycat comes with a twist

**Source:** ESET WeLiveSecurity
**Published:** 2025-09-16
**Article:** https://www.welivesecurity.com/en/videos/hybridpetya-petya-notpetya-copycat-twist/

## Threat Profile

HybridPetya: A Petya/NotPetya copycat comes with a twist 
Video
HybridPetya: The Petya/NotPetya copycat comes with a twist HybridPetya is the fourth publicly known real or proof-of-concept bootkit with UEFI Secure Boot bypass functionality
Editor 
16 Sep 2025 
ESET researchers have uncovered a new ransomware strain that they have named HybridPetya. While resembling the infamous Petya/NotPetya malware, it comes with a new and dangerous twist – it adds the ability to compromise UEFI-based systems …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-7344`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1068** — Exploitation for Privilege Escalation
- **T1553.006** — Subvert Trust Controls: Code Signing Policy Modification
- **T1529** — System Shutdown/Reboot

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] HybridPetya bootkit artefacts written to EFI System Partition (\EFI\Microsoft\Boot\)

`UC_341_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.file_path="*\\EFI\\Microsoft\\Boot\\*" AND (Filesystem.file_name="cloak.dat" OR Filesystem.file_name="bootmgfw.efi.old" OR Filesystem.file_name="verify" OR Filesystem.file_name="counter" OR Filesystem.file_name="config") by Filesystem.dest Filesystem.user Filesystem.process_guid Filesystem.file_path Filesystem.file_name Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\EFI\Microsoft\Boot\"
| where FileName in~ ("cloak.dat","bootmgfw.efi.old","verify","counter","config")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### [LLM] HybridPetya installer / bootkit / cloak.dat SHA-1 hash match

`UC_341_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("9B0EE05FFFDA0B16CF9DAAC587CB92BB06D3981B","3393A8C258239D6802553FD1CCE397E18FA285A1","A6EBFA062270A321241439E8DF72664CD54EA1BC","C7C270F9D3AE80EC5E8926A3CD1FB5C9D208F1DC","C8E3F1BF0B67C83D2A6D9E594DE8067F0378E6C5","CDC8CB3D211589202B49A48618B0D90C4D8F86FD","D31F86BA572904192D7476CA376686E76E103D28","BD35908D5A5E9F7E41A61B7AB598AB9A88DB723D","9DF922D00171AA3C31B75446D700EE567F8D787B","D0BD283133A80B47137562F2AAAB740FA15E6441","98C3E659A903E74D2EE398464D3A5109E92BD9A9") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("9B0EE05FFFDA0B16CF9DAAC587CB92BB06D3981B","3393A8C258239D6802553FD1CCE397E18FA285A1","A6EBFA062270A321241439E8DF72664CD54EA1BC","C7C270F9D3AE80EC5E8926A3CD1FB5C9D208F1DC","C8E3F1BF0B67C83D2A6D9E594DE8067F0378E6C5","CDC8CB3D211589202B49A48618B0D90C4D8F86FD","D31F86BA572904192D7476CA376686E76E103D28","BD35908D5A5E9F7E41A61B7AB598AB9A88DB723D","9DF922D00171AA3C31B75446D700EE567F8D787B","D0BD283133A80B47137562F2AAAB740FA15E6441","98C3E659A903E74D2EE398464D3A5109E92BD9A9") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`]
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let HybridPetyaSHA1 = dynamic([
  "9B0EE05FFFDA0B16CF9DAAC587CB92BB06D3981B",
  "3393A8C258239D6802553FD1CCE397E18FA285A1",
  "A6EBFA062270A321241439E8DF72664CD54EA1BC",
  "C7C270F9D3AE80EC5E8926A3CD1FB5C9D208F1DC",
  "C8E3F1BF0B67C83D2A6D9E594DE8067F0378E6C5",
  "CDC8CB3D211589202B49A48618B0D90C4D8F86FD",
  "D31F86BA572904192D7476CA376686E76E103D28",
  "BD35908D5A5E9F7E41A61B7AB598AB9A88DB723D",
  "9DF922D00171AA3C31B75446D700EE567F8D787B",
  "D0BD283133A80B47137562F2AAAB740FA15E6441",
  "98C3E659A903E74D2EE398464D3A5109E92BD9A9"]);
union isfuzzy=true
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (HybridPetyaSHA1) or InitiatingProcessSHA1 in (HybridPetyaSHA1)
  | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1,
            ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA1,
            Source = "DeviceProcessEvents" ),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (HybridPetyaSHA1)
  | project Timestamp, DeviceName, InitiatingProcessAccountName as AccountName,
            FileName, FolderPath, SHA1,
            InitiatingProcessCommandLine as ProcessCommandLine,
            InitiatingProcessFileName, InitiatingProcessSHA1,
            Source = "DeviceFileEvents" ),
( DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA1 in (HybridPetyaSHA1)
  | project Timestamp, DeviceName, InitiatingProcessAccountName as AccountName,
            FileName, FolderPath, SHA1,
            InitiatingProcessCommandLine as ProcessCommandLine,
            InitiatingProcessFileName, InitiatingProcessSHA1,
            Source = "DeviceImageLoadEvents" )
| order by Timestamp desc
```

### [LLM] NotPetya-style forced reboot via NtRaiseHardError 0xC0000350 from non-system process

`UC_341_6` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.user!="SYSTEM" Processes.user!="LOCAL SERVICE" Processes.user!="NETWORK SERVICE" (Processes.process="*NtRaiseHardError*" OR Processes.process="*0xC0000350*" OR Processes.process="*shutdown* /r* /t 0*" OR Processes.process="*shutdown* -r -t 0*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| join type=inner dest [
    search index=wineventlog (EventCode=1074 OR EventCode=6008)
    | rename ComputerName as dest, _time as shutdownTime
    | fields dest shutdownTime EventCode
  ]
| eval delaySec = shutdownTime - lastTime
| where delaySec >= 0 AND delaySec <= 600
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let WindowSec = 600;
let HardErrorCallers = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where AccountName !endswith "$"
    | where AccountName !in~ ("system","local service","network service")
    | where ProcessCommandLine has_any ("NtRaiseHardError","0xC0000350","C0000350")
        or (FileName =~ "shutdown.exe" and ProcessCommandLine matches regex @"(?i)[/-]r\b.*[/-]t\s*0\b")
    | project HardErrorTime = Timestamp, DeviceId, DeviceName, AccountName,
              FileName, ProcessCommandLine, InitiatingProcessFileName;
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("PowerEventChanged","DeviceShutdown","BugCheckEvent")
| join kind=inner HardErrorCallers on DeviceId
| where Timestamp between (HardErrorTime .. HardErrorTime + WindowSec * 1s)
| project HardErrorTime, ShutdownTime = Timestamp, DelaySec = datetime_diff('second', Timestamp, HardErrorTime),
          DeviceName, AccountName, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by HardErrorTime desc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-7344`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
