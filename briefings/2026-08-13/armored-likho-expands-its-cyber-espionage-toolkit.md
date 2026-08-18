# [HIGH] Armored Likho expands its cyber-espionage toolkit

**Source:** Securelist (Kaspersky)
**Published:** 2026-08-13
**Article:** https://securelist.com/armored-likho-still-toolkit/121033/

## Threat Profile

Table of Contents
Background 
Initial infection 
Still Sync 
How it works 
Telegram data collection 
Still Audio 
The eavesdropping process 
Infrastructure 
Victims 
Attribution 
Takeaways 
Indicators of compromise 
Authors
Konstantin Isakov 
In May 2026, we discovered a new cyber-espionage campaign by the Armored Likho group, also known as Eagle Werewolf, that targets private individuals and organizations across various industries in Russia, including major corporations, the public sector, IT, …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `187.127.153.38`
- **IPv4 (defanged):** `159.198.37.74`
- **IPv4 (defanged):** `213.252.244.123`
- **IPv4 (defanged):** `23.26.237.250`
- **IPv4 (defanged):** `23.27.24.30`
- **IPv4 (defanged):** `188.212.124.178`
- **IPv4 (defanged):** `145.223.69.143`
- **IPv4 (defanged):** `145.223.68.66`
- **Domain (defanged):** `orderapiserver.info`
- **Domain (defanged):** `tg4service.com`
- **Domain (defanged):** `srwinservice.com`
- **Domain (defanged):** `screenserv.com`
- **Domain (defanged):** `windowserv.net`
- **Domain (defanged):** `managementapiservice.com`
- **Domain (defanged):** `service8date.com`
- **Domain (defanged):** `updateservs.com`
- **SHA256:** `c1d1ee16b92e6a138ffa048855f75d7d17674b250d8b422a50a86c9ff207186d`
- **SHA256:** `62801f6223e860a7cca271522e303b2d68f0365d2fa8c828d012d8859e52a773`
- **SHA256:** `4bd7c352ae277b0e38d07beedd4dd507d4bc09fb10ea2a5dc0bcbeeda5e5afdd`
- **SHA256:** `2ca8adbab98ebe305eacf272cf48f5a03ac41b097236a7723821848ae31ef141`
- **MD5:** `439255736797bc88bd19f282449e0436`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573** — Encrypted Channel
- **T1608.001** — Stage Capabilities: Upload Malware
- **T1543.003** — Create or Modify System Process: Windows Service
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1539** — Steal Web Session Cookie
- **T1005** — Data from Local System
- **T1583.001** — Acquire Infrastructure: Domains

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Armored Likho Still Sync gRPC C2 beacon (tg4service.com / still.rpc.Sync)

`UC_62_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*still.rpc.Sync/RegisterMachine*" OR Web.url="*still.rpc.Sync/GetMachineSettings*" OR Web.url="*still.rpc.Sync/CheckFiles*" OR Web.dest="tg4service.com") by Web.src Web.dest Web.dest_port Web.url Web.http_method Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "tg4service.com"
   or RemoteUrl has_any ("still.rpc.Sync/RegisterMachine","still.rpc.Sync/GetMachineSettings","still.rpc.Sync/CheckFiles")
   or RemoteIP == "159.198.37.74"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessSHA256
| order by Timestamp desc
```

### Armored Likho Tauri donation-app dropper C2 (orderapiserver.info catalog endpoints)

`UC_62_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.dest="orderapiserver.info" OR Web.url="*orderapiserver.info/public/categories*" OR Web.url="*orderapiserver.info/public/products*") by Web.src Web.dest Web.url Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "orderapiserver.info" or RemoteIP == "187.127.153.38"
| where RemoteUrl has_any ("/public/categories","/public/products") or RemoteUrl has "orderapiserver.info"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Still Sync TReload service persistence + implant CLI flags (--firefly/--console)

`UC_62_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*--firefly*" OR Processes.process="*--console*" OR Processes.process="*STILL_SYNC_ADDR*" OR Processes.process="*STILL_SEND_PATH*" OR Processes.process="*STILL_TELEGRAM_PASSCODE*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType == "ServiceInstalled"
 | where AdditionalFields has "TReload" or RegistryValueData has "TReload"
 | project Timestamp, DeviceName, AccountName, ActionType, ReportedField=tostring(AdditionalFields), InitiatingProcessFileName, InitiatingProcessFolderPath),
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where ProcessCommandLine has_any ("--firefly","STILL_SYNC_ADDR","STILL_SEND_PATH","STILL_TELEGRAM_PASSCODE")
 | project Timestamp, DeviceName, AccountName, ActionType="ProcessCreate", ReportedField=ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath)
| order by Timestamp desc
```

### Still Sync Telegram tdata theft via non-Telegram process + SeBackupPrivilege abuse

`UC_62_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Telegram Desktop\\tdata\\*" OR Filesystem.file_path="*LocalCache\\Roaming\\*tdata*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | search process_name!="Telegram.exe" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\Telegram Desktop\tdata" or (FolderPath has "tdata" and FolderPath has_any ("LocalCache\\Roaming","TelegramMessenge"))
| where InitiatingProcessFileName !in~ ("Telegram.exe","Update.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize FileCount=dcount(FileName), SampleFiles=make_set(FileName, 10), any(FolderPath) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessAccountName, bin(Timestamp, 10m)
| where FileCount >= 3
| order by Timestamp desc
```

### Armored Likho Still Toolkit C2 infrastructure IOC match (domains + IPs)

`UC_62_9` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("187.127.153.38","159.198.37.74","213.252.244.123","23.26.237.250","23.27.24.30","188.212.124.178","145.223.69.143","145.223.68.66") OR All_Traffic.dest IN ("orderapiserver.info","tg4service.com","srwinservice.com","screenserv.com","windowserv.net","managementapiservice.com","service8date.com","updateservs.com")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let iocDomains = dynamic(["orderapiserver.info","tg4service.com","srwinservice.com","screenserv.com","windowserv.net","managementapiservice.com","service8date.com","updateservs.com"]);
let iocIPs = dynamic(["187.127.153.38","159.198.37.74","213.252.244.123","23.26.237.250","23.27.24.30","188.212.124.178","145.223.69.143","145.223.68.66"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (iocIPs) or RemoteUrl has_any (iocDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, RemoteIP, RemotePort, RemoteUrl
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

### Article-specific behavioural hunt — Armored Likho expands its cyber-espionage toolkit

`UC_62_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Armored Likho expands its cyber-espionage toolkit ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("libmp3lame.dll","intaudio.exe") OR Processes.process_path="*\AppData\Roaming\Telegram*" OR Processes.process_path="*\AppData\Local\Packages\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*\AppData\Roaming\Telegram*" OR Filesystem.file_path="*\AppData\Local\Packages\*" OR Filesystem.file_name IN ("libmp3lame.dll","intaudio.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Armored Likho expands its cyber-espionage toolkit
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("libmp3lame.dll", "intaudio.exe") or FolderPath has_any ("\AppData\Roaming\Telegram", "\AppData\Local\Packages\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("\AppData\Roaming\Telegram", "\AppData\Local\Packages\") or FileName in~ ("libmp3lame.dll", "intaudio.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `187.127.153.38`, `159.198.37.74`, `213.252.244.123`, `23.26.237.250`, `23.27.24.30`, `188.212.124.178`, `145.223.69.143`, `145.223.68.66` _(+8 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c1d1ee16b92e6a138ffa048855f75d7d17674b250d8b422a50a86c9ff207186d`, `62801f6223e860a7cca271522e303b2d68f0365d2fa8c828d012d8859e52a773`, `4bd7c352ae277b0e38d07beedd4dd507d4bc09fb10ea2a5dc0bcbeeda5e5afdd`, `2ca8adbab98ebe305eacf272cf48f5a03ac41b097236a7723821848ae31ef141`, `439255736797bc88bd19f282449e0436`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
