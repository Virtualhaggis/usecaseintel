# [HIGH] Sol Searching | Can Frontier Models Tackle Autonomous Long-Horizon Malware Analysis?

**Source:** SentinelLabs
**Published:** 2026-07-22
**Article:** https://www.sentinelone.com/labs/frontier-models-tackle-autonomous-long-horizon-malware-analysis/

## Threat Profile

AI Research 
Sol Searching | Can Frontier Models Tackle Autonomous Long-Horizon Malware Analysis? 
Juan Andrés Guerrero-Saade & Gabriel Bernadett-Shapiro 
/
July 22, 2026 
Executive Summary 
SentinelLABS developed a multi-stage reverse-engineering benchmark for the latest generation of frontier models by recreating our recent investigation of fast16 , a unique 2005 sabotage implant.
Most AI benchmarks test bounded tasks. This benchmark tests whether a model can keep a malware investigation trust…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525`
- **SHA256:** `07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529`
- **SHA256:** `8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9`
- **SHA1:** `de584703c78a60a56028f9834086facd1401b355`
- **SHA1:** `92e9dcaf7249110047ef121b7586c81d4b8cb4e5`
- **SHA1:** `675cb83cec5f25ebbe8d9f90dea3d836fcb1c234`
- **MD5:** `dbe51eabebf9d4ef9581ef99844a2944`
- **MD5:** `0ff6abe0252d4f37a196a1231fae5f26`
- **MD5:** `410eddfc19de44249897986ecc8ac449`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1543.003** — Persistence (article-specific)
- **T1569.002** — System Services: Service Execution
- **T1059** — Command and Scripting Interpreter
- **T1014** — Rootkit
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1565** — Data Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### fast16 sabotage implant carrier (svcmgmt.exe) by hash / Lua-carrier behaviour

`UC_127_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash IN ("9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525","07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529","8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9","de584703c78a60a56028f9834086facd1401b355","92e9dcaf7249110047ef121b7586c81d4b8cb4e5","675cb83cec5f25ebbe8d9f90dea3d836fcb1c234","dbe51eabebf9d4ef9581ef99844a2944","0ff6abe0252d4f37a196a1231fae5f26","410eddfc19de44249897986ecc8ac449") OR Processes.process_name="svcmgmt.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let fast16_sha256 = dynamic(["9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525","07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529","8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9"]);
let fast16_md5 = dynamic(["dbe51eabebf9d4ef9581ef99844a2944","0ff6abe0252d4f37a196a1231fae5f26","410eddfc19de44249897986ecc8ac449"]);
DeviceProcessEvents
| where Timestamp > ago(90d)
| where SHA256 in~ (fast16_sha256)
   or MD5 in~ (fast16_md5)
   or (FileName =~ "svcmgmt.exe" and ProcessCommandLine has_any (".lua","lua","fast16"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, MD5,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### fast16 kernel driver (fast16.sys) drop / load — sabotage patching engine

`UC_127_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="fast16.sys" by Filesystem.dest Filesystem.file_path Filesystem.process_name Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(90d)
| where FileName =~ "fast16.sys"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| union (
    DeviceFileEvents
    | where Timestamp > ago(90d)
    | where FileName =~ "fast16.sys"
    | project Timestamp, DeviceName, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
  )
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Sol Searching | Can Frontier Models Tackle Autonomous Long-Horizon Malware Analy

`UC_127_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Sol Searching | Can Frontier Models Tackle Autonomous Long-Horizon Malware Analy ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("svcmgmt.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("svcmgmt.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Sol Searching | Can Frontier Models Tackle Autonomous Long-Horizon Malware Analy
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("svcmgmt.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("svcmgmt.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `9a10e1faa86a5d39417cae44da5adf38824dfb9a16432e34df766aa1dc9e3525`, `07c69fc33271cf5a2ce03ac1fed7a3b16357aec093c5bf9ef61fbfa4348d0529`, `8fcb4d3d4df61719ee3da98241393779290e0efcd88a49e363e2a2dfbc04dae9`, `de584703c78a60a56028f9834086facd1401b355`, `92e9dcaf7249110047ef121b7586c81d4b8cb4e5`, `675cb83cec5f25ebbe8d9f90dea3d836fcb1c234`, `dbe51eabebf9d4ef9581ef99844a2944`, `0ff6abe0252d4f37a196a1231fae5f26` _(+1 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
