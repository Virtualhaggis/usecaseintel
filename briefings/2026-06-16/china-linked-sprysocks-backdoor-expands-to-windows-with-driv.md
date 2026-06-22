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
- **T1547.006** — Kernel Modules and Extensions
- **T1055.013** — Process Doppelgänging
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1547.012** — Boot or Logon Autostart Execution: Print Processors
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1095** — Non-Application Layer Protocol
- **T1542.003** — Pre-OS Boot: Bootkit

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SprySOCKS WIN_DRV encrypted kernel-driver containers dropped (KW1B/KX1B .dat)

`UC_131_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="KW1B5206BDC1743FP.dat" OR Filesystem.file_name="KX1B5206BDC1743DD.dat") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("KW1B5206BDC1743FP.dat", "KX1B5206BDC1743DD.dat")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### SprySOCKS WIN_PLUS: Print Spooler (spoolsv.exe) spawning svchost.exe injection target

`UC_131_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="spoolsv.exe" Processes.process_name="svchost.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "spoolsv.exe"
| where FileName =~ "svchost.exe"
| project Timestamp, DeviceName, AccountName,
          ParentCmd = InitiatingProcessCommandLine, ParentPath = InitiatingProcessFolderPath,
          ChildPath = FolderPath, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Custom Print Processor persistence registration (non-winprint.dll Driver)

`UC_131_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Control\\Print\\Environments\\*Print Processors*" Registry.registry_value_name="Driver" Registry.registry_value_data!="winprint.dll" by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_id | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Control\Print\Environments\" and RegistryKey has "Print Processors"
| where RegistryValueName =~ "Driver"
| where RegistryValueData !~ "winprint.dll"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Kernel driver service installed with .dat or non-standard ImagePath

`UC_131_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentControlSet\\Services\\*\\ImagePath" (Registry.registry_value_data="*.dat*" OR (Registry.registry_value_data="*.sys*" AND Registry.registry_value_data!="*\\System32\\drivers\\*" AND Registry.registry_value_data!="*\\System32\\DriverStore\\*")) by Registry.dest Registry.registry_path Registry.registry_value_data Registry.process_id | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\CurrentControlSet\Services\"
| where RegistryValueName =~ "ImagePath"
| where (RegistryValueData has ".dat")
    or (RegistryValueData has ".sys"
        and RegistryValueData !has @"\System32\drivers\"
        and RegistryValueData !has @"\System32\DriverStore\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### SprySOCKS C2 egress to Vultr 207.148.64.0/20 (TCP/443, UDP/53, WS/80)

`UC_131_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="207.148.64.0/20" by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.transport All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ipv4_is_in_range(RemoteIP, "207.148.64.0/20")
    or (InitiatingProcessFileName =~ "svchost.exe"
        and InitiatingProcessParentFileName =~ "spoolsv.exe"
        and RemoteIPType == "Public")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Exposure hunt: unpatched CVE-2023-24932 Boot Manager (BlackLotus/UEFI bootkit risk)

`UC_131_9` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2023-24932"
| project DeviceId, DeviceName, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, RecommendedSecurityUpdate, VulnerabilitySeverityLevel
| order by DeviceName asc
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

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
