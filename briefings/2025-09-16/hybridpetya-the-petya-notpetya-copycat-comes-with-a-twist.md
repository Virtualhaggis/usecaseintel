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
- **T1490** — Inhibit System Recovery
- **T1204.002** — User Execution: Malicious File
- **T1222.001** — File and Directory Permissions Modification: Windows File and Directory Permissions Modification

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] HybridPetya bootkit drop on EFI System Partition (cloak.dat / bootmgfw.efi.old / verify / counter)

`UC_355_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files_written values(Filesystem.process_guid) as process_guid from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\EFI\\Microsoft\\Boot\\*" AND Filesystem.file_name IN ("cloak.dat","bootmgfw.efi.old","verify","counter","config") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | join type=left process_guid [| tstats summariesonly=t values(Processes.process_name) as process_name values(Processes.process) as process values(Processes.process_hash) as process_hash from datamodel=Endpoint.Processes by Processes.process_guid | rename Processes.process_guid as process_guid | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where FolderPath has @"\EFI\Microsoft\Boot" or FolderPath has @"\EFI\Boot"
| where FileName in~ ("cloak.dat", "bootmgfw.efi.old", "verify", "counter", "config")
| where ActionType in ("FileCreated", "FileRenamed", "FileModified")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA1, InitiatingProcessFileName, InitiatingProcessSHA1, InitiatingProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessParentFileName
| join kind=leftouter (DeviceProcessEvents | project DeviceId, InitiatingProcessId=ProcessId, InitiatingProcessCreationTime=ProcessCreationTime, ProcessCommandLine) on DeviceId, InitiatingProcessId, InitiatingProcessCreationTime
```

### [LLM] HybridPetya installer execution by hash or known filename

`UC_355_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name values(Processes.process_hash) as process_hash from datamodel=Endpoint.Processes where (Processes.process_hash IN ("9B0EE05FFFDA0B16CF9DAAC587CB92BB06D3981B","CDC8CB3D211589202B49A48618B0D90C4D8F86FD","D31F86BA572904192D7476CA376686E76E103D28","A6EBFA062270A321241439E8DF72664CD54EA1BC","C8E3F1BF0B67C83D2A6D9E594DE8067F0378E6C5","C7C270F9D3AE80EC5E8926A3CD1FB5C9D208F1DC","3393A8C258239D6802553FD1CCE397E18FA285A1","D0BD283133A80B47137562F2AAAB740FA15E6441","BD35908D5A5E9F7E41A61B7AB598AB9A88DB723D","9DF922D00171AA3C31B75446D700EE567F8D787B") OR Processes.process_name IN ("notpetyanew.exe","improved_notpetyanew.exe","notpetya_new.exe","notpetyanew_improved_final.exe","f20000.mbam_update.exe")) by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let hybridpetya_sha1 = dynamic(["9B0EE05FFFDA0B16CF9DAAC587CB92BB06D3981B","CDC8CB3D211589202B49A48618B0D90C4D8F86FD","D31F86BA572904192D7476CA376686E76E103D28","A6EBFA062270A321241439E8DF72664CD54EA1BC","C8E3F1BF0B67C83D2A6D9E594DE8067F0378E6C5","C7C270F9D3AE80EC5E8926A3CD1FB5C9D208F1DC","3393A8C258239D6802553FD1CCE397E18FA285A1","D0BD283133A80B47137562F2AAAB740FA15E6441","BD35908D5A5E9F7E41A61B7AB598AB9A88DB723D","9DF922D00171AA3C31B75446D700EE567F8D787B"]);
let hybridpetya_names = dynamic(["notpetyanew.exe","improved_notpetyanew.exe","notpetya_new.exe","notpetyanew_improved_final.exe","f20000.mbam_update.exe","core.dll"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where SHA1 in~ (hybridpetya_sha1) or FileName in~ (hybridpetya_names) or InitiatingProcessSHA1 in~ (hybridpetya_sha1)
    | project Timestamp, DeviceName, EventType="Process", FileName, FolderPath, SHA1, ProcessCommandLine, AccountName, InitiatingProcessFileName, InitiatingProcessSHA1),
  (DeviceFileEvents
    | where SHA1 in~ (hybridpetya_sha1) or FileName in~ (hybridpetya_names)
    | project Timestamp, DeviceName, EventType="File", FileName, FolderPath, SHA1, ProcessCommandLine=InitiatingProcessCommandLine, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessSHA1)
```

### [LLM] mountvol assigning EFI System Partition drive letter prior to ESP file writes

`UC_355_6` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.process_name="mountvol.exe" AND (Processes.process="*/S*" OR Processes.process="* /s*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_guid _time | `drop_dm_object_name(Processes)` | rename _time as mount_time | join type=inner dest [| tstats summariesonly=t values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name min(_time) as write_time from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\EFI\\*" OR Filesystem.file_name IN ("cloak.dat","bootmgfw.efi","bootmgfw.efi.old")) by Filesystem.dest Filesystem.process_guid | `drop_dm_object_name(Filesystem)`] | where write_time >= mount_time AND (write_time - mount_time) < 600 | table firstTime dest user parent_process_name process file_name file_path
```

**Defender KQL:**
```kql
let mounts = DeviceProcessEvents
  | where FileName =~ "mountvol.exe" and ProcessCommandLine has_any ("/S", " -S", "/s")
  | project DeviceId, DeviceName, MountTime=Timestamp, MountCmd=ProcessCommandLine, MountInitiator=InitiatingProcessFileName, MountAccount=AccountName;
let esp_writes = DeviceFileEvents
  | where FolderPath has @"\EFI\" or FileName in~ ("cloak.dat","bootmgfw.efi","bootmgfw.efi.old","verify","counter")
  | where ActionType in ("FileCreated","FileRenamed","FileModified")
  | project DeviceId, WriteTime=Timestamp, FolderPath, FileName, SHA1, InitiatingProcessFileName, InitiatingProcessSHA1, InitiatingProcessCommandLine;
mounts
| join kind=inner esp_writes on DeviceId
| where WriteTime between (MountTime .. MountTime + 10m)
| project MountTime, WriteTime, DeviceName, MountCmd, MountInitiator, MountAccount, FolderPath, FileName, SHA1, InitiatingProcessFileName, InitiatingProcessCommandLine
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
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
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
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-7344`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
