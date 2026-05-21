# [CRIT] Hackers Use Fake Income Tax Assessment Pages to Infect Windows Systems

**Source:** Cyber Security News
**Published:** 2026-05-20
**Article:** https://cybersecuritynews.com/hackers-use-fake-income-tax-assessment-pages/

## Threat Profile

Home Cyber Security News 
Hackers Use Fake Income Tax Assessment Pages to Infect Windows Systems 
By Tushar Subhra Dutta 
May 20, 2026 
A new threat campaign is targeting Windows users in India by disguising malicious files as official income tax documents. 
Researchers have tracked the operation under the name TAX#TRIDENT, and it has shown the ability to pivot across multiple delivery methods while keeping the same convincing tax lure intact. 
The attack does not rely on any technical vulnerabi…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `149.104.24.197`
- **IPv4 (defanged):** `45.119.55.66`
- **IPv4 (defanged):** `216.250.104.166`
- **IPv4 (defanged):** `202.61.160.201`
- **Domain (defanged):** `zyisykm.shop`
- **Domain (defanged):** `gooomld.top`
- **Domain (defanged):** `goolmor.cyou`
- **Domain (defanged):** `fgsdol.icu`
- **Domain (defanged):** `vsdnk.top`
- **Domain (defanged):** `gooomoel.shop`
- **Domain (defanged):** `tengxxi.com`
- **Domain (defanged):** `xhxz.info`
- **SHA256:** `950ad7a33457a1a37a0797316cdd2fbaf9850f7165425274351d08b3c01ed2d8`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1543.003** — Persistence (article-specific)
- **T1204.002** — User Execution: Malicious File
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1105** — Ingress Tool Transfer
- **T1548.002** — Abuse Elevation Control Mechanism: Bypass User Account Control
- **T1112** — Modify Registry
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1014** — Rootkit
- **T1547.006** — Boot or Logon Autostart Execution: Kernel Modules and Extensions
- **T1036.008** — Masquerading: Masquerade File Type
- **T1027.009** — Obfuscated Files or Information: Embedded Payloads
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1219** — Remote Access Software
- **T1571** — Non-Standard Port

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] TAX#TRIDENT ClientSetup execution with C2 IP embedded in filename

`UC_13_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="*ClientSetup.exe" by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | where match(process_name, "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\\\\]*ClientSetup\.exe$") OR process_hash="950ad7a33457a1a37a0797316cdd2fbaf9850f7165425274351d08b3c01ed2d8" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName matches regex @"(?i)^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\\]*\.exe$" and FileName has "ClientSetup")
   or SHA256 =~ "950ad7a33457a1a37a0797316cdd2fbaf9850f7165425274351d08b3c01ed2d8"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] TAX#TRIDENT UAC bypass: ConsentPromptBehaviorAdmin set to 0 by script engine

`UC_13_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Microsoft\\Windows\\CurrentVersion\\Policies\\System*" Registry.registry_value_name="ConsentPromptBehaviorAdmin" (Registry.registry_value_data="0x00000000" OR Registry.registry_value_data="0") by Registry.dest Registry.user Registry.process_name Registry.process Registry.registry_path Registry.registry_value_data | `drop_dm_object_name(Registry)` | where process_name IN ("wscript.exe","cscript.exe","powershell.exe","pwsh.exe","mshta.exe","cmd.exe","reg.exe") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Microsoft\Windows\CurrentVersion\Policies\System"
| where RegistryValueName =~ "ConsentPromptBehaviorAdmin"
| where RegistryValueData in ("0", "0x0", "0x00000000", "DWORD (0x00000000)")
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "cmd.exe", "reg.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] TAX#TRIDENT ClientSetup persistence: MANC service + YtMiniFilter/ytdisk driver registration

`UC_13_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentControlSet\\Services\\MANC*" OR Registry.registry_path="*\\CurrentControlSet\\Services\\YtMiniFilter*" OR Registry.registry_path="*\\CurrentControlSet\\Services\\ytdisk*") by Registry.dest Registry.user Registry.process_name Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let svcReg = DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where RegistryKey has @"\CurrentControlSet\Services\"
    | where RegistryKey has_any ("MANC", "YtMiniFilter", "ytdisk")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine;
let driverFiles = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName has_any ("YtMiniFilter", "ytdisk", "YTSysConfig.ini", "YTSysConfig.ytf")
       or FolderPath has @"\Windows\SysWOW64\msres\"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine;
union svcReg, driverFiles
| order by Timestamp desc
```

### [LLM] Script engine executing files disguised with image/web extensions (TAX#TRIDENT uacMC.png pattern)

`UC_13_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") by Processes.dest Processes.user Processes.process Processes.process_name Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where match(process, "(?i)\.(png|jpg|jpeg|gif|webp|svg|php)(\s|\"|$)") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine matches regex @"(?i)\.(png|jpg|jpeg|gif|webp|svg|php)(\s|""|$)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Outbound connection to TAX#TRIDENT C2 infrastructure (IPs, ports, lure domains)

`UC_13_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("45.119.55.66","216.250.104.166","202.61.160.201","149.104.24.197")) OR (All_Traffic.dest_ip="45.119.55.66" AND All_Traffic.dest_port IN (6671,6681,6683)) OR (All_Traffic.dest_ip="202.61.160.201" AND All_Traffic.dest_port IN (8383,8027)) by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let c2Ips = dynamic(["45.119.55.66","216.250.104.166","202.61.160.201","149.104.24.197"]);
let lureDomains = dynamic(["zyisykm.shop","gooomld.top","goolmor.cyou","fgsdol.icu","vsdnk.top","gooomoel.shop","tengxxi.com","xhxz.info"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2Ips)
   or (RemoteIP == "45.119.55.66" and RemotePort in (6671, 6681, 6683))
   or (RemoteIP == "202.61.160.201" and RemotePort in (8383, 8027))
   or (isnotempty(RemoteUrl) and parse_url(RemoteUrl).Host has_any (lureDomains))
   or RemoteUrl has_any (lureDomains)
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
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

### Article-specific behavioural hunt — Hackers Use Fake Income Tax Assessment Pages to Infect Windows Systems

`UC_13_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Use Fake Income Tax Assessment Pages to Infect Windows Systems ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("assessment_order.vbs","45.119.55.66clientsetup.exe","250.104.166clientsetup.exe","216.250.104.166clientsetup.exe") OR Processes.process_path="*C:\Windows\SysWOW64\msres\*" OR Processes.process_path="*C:\Users\Public\Documents\MSUpdate_*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\SysWOW64\msres\*" OR Filesystem.file_path="*C:\Users\Public\Documents\MSUpdate_*" OR Filesystem.file_name IN ("assessment_order.vbs","45.119.55.66clientsetup.exe","250.104.166clientsetup.exe","216.250.104.166clientsetup.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Use Fake Income Tax Assessment Pages to Infect Windows Systems
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("assessment_order.vbs", "45.119.55.66clientsetup.exe", "250.104.166clientsetup.exe", "216.250.104.166clientsetup.exe") or FolderPath has_any ("C:\Windows\SysWOW64\msres\", "C:\Users\Public\Documents\MSUpdate_"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\SysWOW64\msres\", "C:\Users\Public\Documents\MSUpdate_") or FileName in~ ("assessment_order.vbs", "45.119.55.66clientsetup.exe", "250.104.166clientsetup.exe", "216.250.104.166clientsetup.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `149.104.24.197`, `45.119.55.66`, `216.250.104.166`, `202.61.160.201`, `zyisykm.shop`, `gooomld.top`, `goolmor.cyou`, `fgsdol.icu` _(+4 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `950ad7a33457a1a37a0797316cdd2fbaf9850f7165425274351d08b3c01ed2d8`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
