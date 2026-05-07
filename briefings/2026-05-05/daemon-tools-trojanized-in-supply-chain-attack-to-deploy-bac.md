# [HIGH] DAEMON Tools trojanized in supply-chain attack to deploy backdoor

**Source:** BleepingComputer
**Published:** 2026-05-05
**Article:** https://www.bleepingcomputer.com/news/security/daemon-tools-trojanized-in-supply-chain-attack-to-deploy-backdoor/

## Threat Profile

DAEMON Tools trojanized in supply-chain attack to deploy backdoor 
By Bill Toulas 
May 5, 2026
03:21 PM
0 
Hackers trojanized installers for the DAEMON Tools software and since April 8, delivered a backdoor to thousands of systems that downloaded the product from the official website.
The supply-chain attack led to thousands of infections in more than 100 countries. However, second-stage payloads were deployed only to a dozen machines, indicating a targeted attack aimed at high-value targets.
Am…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1543.003** — Windows Service
- **T1546.012** — Image File Execution Options Injection
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1082** — System Information Discovery
- **T1059.001** — PowerShell
- **T1059.003** — Windows Command Shell
- **T1218.005** — Mshta
- **T1218.011** — Rundll32
- **T1218.010** — Regsvr32
- **T1105** — Ingress Tool Transfer
- **T1055** — Process Injection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Trojanized DAEMON Tools binary creates autorun persistence

`UC_44_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.process_name IN ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe") AND (Registry.registry_path="*\\Run*" OR Registry.registry_path="*\\Image File Execution Options*" OR Registry.registry_path="*\\Services\\*" OR Registry.registry_path="*\\Winlogon\\*") by host Registry.user Registry.process_name Registry.registry_path Registry.registry_key_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > datetime(2026-04-08)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where InitiatingProcessFileName in~ ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe")
| where RegistryKey has_any (@"\Run", @"\RunOnce", @"\Services\", @"\Image File Execution Options\", @"\Winlogon\")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256,
          InitiatingProcessVersionInfoProductVersion, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] DAEMON Tools binary makes outbound public network connection (info-stealer beacon)

`UC_44_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe") AND NOT (All_Traffic.dest IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","169.254.0.0/16")) by host All_Traffic.app All_Traffic.process_name All_Traffic.dest All_Traffic.dest_port All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > datetime(2026-04-08)
| where InitiatingProcessFileName in~ ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe")
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessVersionInfoProductVersion, InitiatingProcessSHA256,
          RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] DAEMON Tools binary spawns interpreter or LOLBin (second-stage / QUIC RAT execution)

`UC_44_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe") AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","msbuild.exe","installutil.exe","hh.exe") by host user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > datetime(2026-04-08)
| where InitiatingProcessFileName in~ ("DTHelper.exe","DiscSoftBusServiceLite.exe","DTShellHlp.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","msbuild.exe","installutil.exe","hh.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentVersion = InitiatingProcessVersionInfoProductVersion,
          ParentSHA256 = InitiatingProcessSHA256,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256
| order by Timestamp desc
```

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — DAEMON Tools trojanized in supply-chain attack to deploy backdoor

`UC_44_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — DAEMON Tools trojanized in supply-chain attack to deploy backdoor ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("dthelper.exe","discsoftbusservicelite.exe","dtshellhlp.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("dthelper.exe","discsoftbusservicelite.exe","dtshellhlp.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — DAEMON Tools trojanized in supply-chain attack to deploy backdoor
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("dthelper.exe", "discsoftbusservicelite.exe", "dtshellhlp.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("dthelper.exe", "discsoftbusservicelite.exe", "dtshellhlp.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
