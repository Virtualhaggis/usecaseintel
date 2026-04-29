# [CRIT] PlushDaemon compromises network devices for adversary-in-the-middle attacks

**Source:** ESET WeLiveSecurity
**Published:** 2025-11-19
**Article:** https://www.welivesecurity.com/en/eset-research/plushdaemon-compromises-network-devices-for-adversary-in-the-middle-attacks/

## Threat Profile

PlushDaemon compromises network devices for adversary-in-the-middle attacks 
ESET Research
PlushDaemon compromises network devices for adversary-in-the-middle attacks ESET researchers have discovered a network implant used by the China-aligned PlushDaemon APT group to perform adversary-in-the-middle attacks
Facundo Muñoz 
Dávid Gábriš 
19 Nov 2025 
 •  
, 
10 min. read 
ESET researchers provide insights into how PlushDaemon performs adversary-in-the-middle attacks using a previously undocumented…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `47.242.198.250`
- **IPv4 (defanged):** `8.212.132.120`
- **Domain (defanged):** `ds20221202.dsc.wcsset.com`
- **Domain (defanged):** `test.dsc.wcsset.com`
- **Domain (defanged):** `wcsset.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1659** — Content Injection
- **T1557** — Adversary-in-the-Middle
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1036.008** — Masquerading: Masquerade File Type
- **T1105** — Ingress Tool Transfer
- **T1071.004** — Application Layer Protocol: DNS
- **T1583.002** — Acquire Infrastructure: DNS Server
- **T1583.004** — Acquire Infrastructure: Server

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — PlushDaemon compromises network devices for adversary-in-the-middle attacks

`UC_287_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — PlushDaemon compromises network devices for adversary-in-the-middle attacks ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("2.0.2246.dll","popup_4.2.0.2246.dll","360tray.exe","plugin.exe","2246.dll","0.2508_0000.exe") OR Processes.process_path="*%PROGRAMDATA%\Tencent\QQUpdateMgr\UpdateFiles\logo.gif*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%PROGRAMDATA%\Tencent\QQUpdateMgr\UpdateFiles\logo.gif*" OR Filesystem.file_path="*/etc/bioset.conf*" OR Filesystem.file_name IN ("2.0.2246.dll","popup_4.2.0.2246.dll","360tray.exe","plugin.exe","2246.dll","0.2508_0000.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — PlushDaemon compromises network devices for adversary-in-the-middle attacks
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("2.0.2246.dll", "popup_4.2.0.2246.dll", "360tray.exe", "plugin.exe", "2246.dll", "0.2508_0000.exe") or FolderPath has_any ("%PROGRAMDATA%\Tencent\QQUpdateMgr\UpdateFiles\logo.gif"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%PROGRAMDATA%\Tencent\QQUpdateMgr\UpdateFiles\logo.gif", "/etc/bioset.conf") or FileName in~ ("2.0.2246.dll", "popup_4.2.0.2246.dll", "360tray.exe", "plugin.exe", "2246.dll", "0.2508_0000.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] PlushDaemon DaemonicLogistics update-hijack URI pattern (Sogou/Baidu)

`UC_287_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user_agent) as ua values(Web.src) as src values(Web.dest) as dest from datamodel=Web.Web where (Web.url IN ("*ime.sogou.com/update/updateInfo.bzp*","*mobads.baidu.com/update/updateInfo.bzp*","*ime.sogou.com/update/latest/new_version?tp=*","*ime.sogou.com/update/file6.bdat*","*ime.sogou.com/update/file2.bdat*") OR (Web.dest="119.136.153.0" AND Web.url="*/update/updateInfo.bzp*")) by Web.src Web.dest Web.url Web.http_method | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any ("ime.sogou.com/update/updateInfo.bzp","mobads.baidu.com/update/updateInfo.bzp","ime.sogou.com/update/file6.bdat","ime.sogou.com/update/file2.bdat") or RemoteUrl matches regex @"ime\.sogou\.com/update/latest/new_version\?tp=\d+" or (RemoteIP == "119.136.153.0" and RemoteUrl has "/update/updateInfo.bzp"))
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| sort by Timestamp desc
```

### [LLM] DaemonicLogistics drops payload as logo.gif under masqueraded Tencent QQUpdateMgr path

`UC_287_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process values(Filesystem.process_path) as proc_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\ProgramData\\Tencent\\QQUpdateMgr\\UpdateFiles\\logo.gif" by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where FolderPath endswith @"\ProgramData\Tencent\QQUpdateMgr\UpdateFiles\logo.gif"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| sort by Timestamp desc
```

### [LLM] PlushDaemon C2/hijack node contact: wcsset.com or known IPs

`UC_287_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer values(DNS.query) as query from datamodel=Network_Resolution.DNS where (DNS.query="*wcsset.com" OR DNS.answer IN ("47.242.198.250","8.212.132.120")) by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("47.242.198.250","8.212.132.120") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
( DeviceNetworkEvents
  | where Timestamp > ago(90d)
  | where RemoteIP in ("47.242.198.250","8.212.132.120") or RemoteUrl has "wcsset.com"
  | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort ),
( DeviceEvents
  | where Timestamp > ago(90d)
  | where ActionType == "DnsQueryResponse"
  | where AdditionalFields has "wcsset.com"
  | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, AdditionalFields )
| sort by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `47.242.198.250`, `8.212.132.120`, `ds20221202.dsc.wcsset.com`, `test.dsc.wcsset.com`, `wcsset.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
