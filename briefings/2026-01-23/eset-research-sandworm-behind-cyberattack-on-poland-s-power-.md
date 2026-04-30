# [HIGH] ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025

**Source:** ESET WeLiveSecurity
**Published:** 2026-01-23
**Article:** https://www.welivesecurity.com/en/eset-research/eset-research-sandworm-cyberattack-poland-power-grid-late-2025/

## Threat Profile

ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025 
ESET Research
ESET Research: Sandworm behind cyberattack on Poland’s power grid in late 2025 The attack involved data-wiping malware that ESET researchers have now analyzed and named DynoWiper
ESET Research 
23 Jan 2026 
 •  
, 
2 min. read 
UPDATE (January 30 th , 2026): For a technical breakdown of the incident affecting a company in Poland’s energy sector, refer to this blogpost . 
In late 2025, Poland’s energy sy…

## Indicators of Compromise (high-fidelity only)

- **SHA1:** `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`

## MITRE ATT&CK Techniques

- **T1027** — Obfuscated Files or Information
- **T1090.001** — Internal Proxy
- **T1572** — Protocol Tunneling
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1485** — Data Destruction
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1570** — Lateral Tool Transfer
- **T1561.001** — Disk Wipe: Disk Content Wipe
- **T1529** — System Shutdown/Reboot

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Sandworm rsocx reverse SOCKS proxy beacon to DynoWiper C2 31.172.71[.]5:8008

`UC_229_1` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("r.exe","rsocx.exe") OR Processes.process="*rsocx*" OR Processes.process="*-r 31.172.71.5*" OR Processes.process="*-r 31.172.71.5:8008*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="31.172.71.5" AND All_Traffic.dest_port=8008 by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let c2_ip = dynamic(["31.172.71.5"]);
let c2_port = 8008;
let rsocx_cmdline = DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("r.exe","rsocx.exe") and FolderPath has_any (@"\Downloads\", @"\Public\", @"\inetpub\"))
   or ProcessCommandLine matches regex @"(?i)\brsocx\b"
   or ProcessCommandLine matches regex @"-r\s+31\.172\.71\.5(:|\s|$)"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine;
let c2_net = DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2_ip) and RemotePort == c2_port
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA1, RemoteIP, RemotePort, ActionType;
union rsocx_cmdline, c2_net
```

### [LLM] DynoWiper staging in C:\inetpub\pub\ as schtask.exe / schtask2.exe / *_update.exe

`UC_229_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\inetpub\\pub\\*" AND (Filesystem.file_name IN ("schtask.exe","schtask2.exe") OR Filesystem.file_name="*_update.exe") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_path="*\\inetpub\\pub\\*" AND (Processes.process_name IN ("schtask.exe","schtask2.exe") OR Processes.process_name="*_update.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let known_hashes_sha1 = dynamic(["4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6","86596A5C5B05A8BFBD14876DE7404702F7D0D61B","69EDE7E341FD26FA0577692B601D80CB44778D93"]);
let file_drops = DeviceFileEvents
| where Timestamp > ago(60d)
| where FolderPath has @"\inetpub\pub\"
| where FileName in~ ("schtask.exe","schtask2.exe") or FileName endswith "_update.exe" or SHA1 in (known_hashes_sha1)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName;
let exec_from_share = DeviceProcessEvents
| where Timestamp > ago(60d)
| where FolderPath has @"\inetpub\pub\"
| where FileName in~ ("schtask.exe","schtask2.exe") or FileName endswith "_update.exe" or SHA1 in (known_hashes_sha1)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA1, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine;
union file_drops, exec_from_share
```

### [LLM] DynoWiper behavior: mass multi-drive file overwrite immediately followed by forced reboot

`UC_229_3` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths dc(Filesystem.file_path) as path_count values(Filesystem.file_name) as files dc(eval(substr(Filesystem.file_path,1,2))) as drive_count from datamodel=Endpoint.Filesystem where Filesystem.action IN ("modified","deleted","created") AND NOT (Filesystem.file_path="*\\Windows\\*" OR Filesystem.file_path="*\\system32\\*" OR Filesystem.file_path="*\\Program Files*" OR Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*\\$Recycle.Bin*" OR Filesystem.file_path="*\\PerfLogs*" OR Filesystem.file_path="*\\Boot\\*") by Filesystem.dest Filesystem.process_guid Filesystem.process_name _time span=5m | `drop_dm_object_name(Filesystem)` | where path_count>500 AND drive_count>=2 | join type=inner dest process_guid [| tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_name IN ("shutdown.exe") OR Processes.process="*ExitWindowsEx*" OR Processes.process="*-r -f -t 0*" by Processes.dest Processes.process_guid Processes.parent_process_guid Processes.process_name Processes.process | `drop_dm_object_name(Processes)`] | table _time dest process_name path_count drive_count files process
```

**Defender KQL:**
```kql
let wipe_window = 10m;
let exclusions = dynamic([@"\windows\",@"\system32\",@"\program files\",@"\program files (x86)\",@"\appdata\",@"\$recycle.bin\",@"\perflogs\",@"\boot\",@"\documents and settings\"]);
let mass_writes = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileModified","FileCreated","FileDeleted","FileRenamed")
| where not(FolderPath has_any (exclusions))
| extend Drive = tolower(substring(FolderPath,0,3))
| summarize FileCount=count(), DriveCount=dcount(Drive), Drives=make_set(Drive,10), SamplePaths=make_set(FolderPath,10) by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessSHA1, bin(Timestamp, wipe_window)
| where FileCount > 500 and DriveCount >= 2;
let reboots = DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "shutdown.exe" and ProcessCommandLine has_any ("/r","-r") and ProcessCommandLine has_any ("/f","-f"))
   or ProcessCommandLine has "ExitWindowsEx"
| project DeviceId, DeviceName, RebootTime=Timestamp, RebootProc=FileName, RebootCmd=ProcessCommandLine, RebootInitiator=InitiatingProcessFileName;
mass_writes
| join kind=inner (reboots) on DeviceId
| where RebootTime between (Timestamp .. Timestamp + 15m)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA1, FileCount, DriveCount, Drives, SamplePaths, RebootTime, RebootProc, RebootCmd
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4EC3C90846AF6B79EE1A5188EEFA3FD21F6D4CF6`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
