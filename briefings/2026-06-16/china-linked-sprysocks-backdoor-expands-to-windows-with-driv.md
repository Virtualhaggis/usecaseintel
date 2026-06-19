# [CRIT] China-Linked SprySOCKS Backdoor Expands to Windows with Driver-Based Stealth

**Source:** The Hacker News
**Published:** 2026-06-16
**Article:** https://thehackernews.com/2026/06/china-linked-sprysocks-backdoor-expands.html

## Threat Profile

China-Linked SprySOCKS Backdoor Expands to Windows with Driver-Based Stealth 
 Ravie Lakshmanan  Jun 16, 2026 Malware / Cyber Espionage 
Cybersecurity researchers have flagged two previously undocumented Windows variants of what was believed to be a Linux-only backdoor called SprySOCKS .
"The Windows variants discovered are internally marked as WIN_DRV and WIN_PLUS," ESET said in a report shared with The Hacker News. "Both come with a hard-coded C&C [command-and-control] configuration and supp…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-24932`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1053.005** — Scheduled Task
- **T1014** — Rootkit
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions
- **T1112** — Modify Registry
- **T1055.012** — Process Injection: Process Hollowing
- **T1547.012** — Boot or Logon Autostart Execution: Print Processors
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1553.006** — Subvert Trust Controls: Code Signing Policy Modification

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SprySOCKS WIN_DRV kernel driver file dropped (KW1B/KX1B *.dat)

`UC_114_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_name="KW1B5206BDC1743FP.dat" OR Filesystem.file_name="KX1B5206BDC1743DD.dat") by Filesystem.dest Filesystem.user Filesystem.process_id Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName matches regex @"(?i)^K[WX]1B5206BDC1743(FP|DD)\.dat$"
   or FileName in~ ("KW1B5206BDC1743FP.dat", "KX1B5206BDC1743DD.dat")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Kernel driver service registered with SprySOCKS WIN_DRV ImagePath

`UC_114_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\System\\CurrentControlSet\\Services\\*" Registry.registry_value_name="ImagePath" AND (Registry.registry_value_data="*KW1B5206BDC1743FP*" OR Registry.registry_value_data="*KX1B5206BDC1743DD*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has @"\System\CurrentControlSet\Services\"
| where RegistryValueName =~ "ImagePath"
| where RegistryValueData has_any ("KW1B5206BDC1743FP", "KX1B5206BDC1743DD")
   or RegistryValueData matches regex @"(?i)K[WX]1B5206BDC1743(FP|DD)\.dat"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### WIN_PLUS Print Spooler abuse: spoolsv.exe spawns svchost.exe

`UC_114_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="spoolsv.exe" Processes.process_name="svchost.exe" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process Processes.parent_process Processes.process_id Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "spoolsv.exe"
| where FileName =~ "svchost.exe"
| project Timestamp, DeviceName, AccountName,
          ParentFolder = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ParentSHA256 = InitiatingProcessSHA256,
          ChildFolder = FolderPath,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256,
          GrandparentName = InitiatingProcessParentFileName
| order by Timestamp desc
```

### Suspicious Print Processor registry persistence (WIN_PLUS T1547.012)

`UC_114_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Control\\Print\\Environments\\*\\Print Processors\\*" Registry.registry_value_name="Driver" Registry.registry_value_data!="winprint.dll" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name Registry.process | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has @"\Control\Print\Environments\"
| where RegistryKey contains "Print Processors"
| where RegistryValueName =~ "Driver"
| where RegistryValueData !endswith "winprint.dll"
| where isnotempty(RegistryValueData)
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### WIN_DRV chain: scheduled task creation followed by SprySOCKS driver drop

`UC_114_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" Processes.process="*create*" (Processes.parent_process_name="cmd.exe" OR Processes.parent_process_name="powershell.exe" OR Processes.parent_process_name="pwsh.exe" OR Processes.parent_process_name="wscript.exe" OR Processes.parent_process_name="cscript.exe") by Processes.dest Processes.user Processes.process Processes.parent_process _time | `drop_dm_object_name(Processes)` | rename _time as task_time | join type=inner dest [ | tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_name="KW1B5206BDC1743FP.dat" OR Filesystem.file_name="KX1B5206BDC1743DD.dat") by Filesystem.dest Filesystem.file_name Filesystem.file_path _time | `drop_dm_object_name(Filesystem)` | rename _time as drop_time dest as dest ] | eval delay_min=round((drop_time-task_time)/60,1) | where delay_min>=0 AND delay_min<=60 | table task_time drop_time delay_min dest user process file_name file_path
```

**Defender KQL:**
```kql
let SchtasksCreate = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine has_any ("/create", "/Create", "-Create")
    | where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe")
    | project TaskTime = Timestamp, DeviceId, DeviceName, AccountName,
              TaskCmd = ProcessCommandLine, TaskParent = InitiatingProcessFileName,
              TaskParentCmd = InitiatingProcessCommandLine;
let DriverDrop = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType == "FileCreated"
    | where FileName matches regex @"(?i)^K[WX]1B5206BDC1743(FP|DD)\.dat$"
    | project DropTime = Timestamp, DeviceId, DriverFile = FileName, DriverPath = FolderPath,
              DropProc = InitiatingProcessFileName, DropProcCmd = InitiatingProcessCommandLine;
SchtasksCreate
| join kind=inner DriverDrop on DeviceId
| where DropTime between (TaskTime .. TaskTime + 1h)
| extend DelayMinutes = datetime_diff('minute', DropTime, TaskTime)
| project TaskTime, DropTime, DelayMinutes, DeviceName, AccountName,
          TaskParent, TaskCmd, DropProc, DropProcCmd, DriverFile, DriverPath
| order by TaskTime desc
```

### CVE-2023-24932 exposure surface — UEFI bootkit pre-OS attack risk

`UC_114_9` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`vulnerabilities` cve="CVE-2023-24932" | stats values(severity) as severity values(cvss) as cvss values(asset_priority) as asset_priority dc(dest) as host_count by dest os | sort 0 - host_count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId =~ "CVE-2023-24932"
| summarize arg_max(Timestamp, *) by DeviceId, CveId
| join kind=inner (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, IsInternetFacing, JoinType, MachineGroup, PublicIP, LoggedOnUsers
  ) on DeviceId
| project Timestamp, DeviceName, OSPlatform, OSVersion, SoftwareName, SoftwareVersion,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId,
          IsInternetFacing, JoinType, MachineGroup, PublicIP, LoggedOnUsers
| order by IsInternetFacing desc, Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-24932`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
