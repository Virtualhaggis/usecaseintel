# [CRIT] DynoWiper update: Technical analysis and attribution

**Source:** ESET WeLiveSecurity
**Published:** 2026-01-30
**Article:** https://www.welivesecurity.com/en/eset-research/dynowiper-update-technical-analysis-attribution/

## Threat Profile

DynoWiper update: Technical analysis and attribution 
ESET Research
DynoWiper update: Technical analysis and attribution ESET researchers present technical details on a recent data destruction incident affecting a company in Poland’s energy sector
ESET Research 
30 Jan 2026 
 •  
, 
13 min. read 
In this blog post, we provide more technical details related to our previous DynoWiper publication.
Key points of the report: 
ESET researchers identified new data-wiping malware that we have named Dyno…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `31.172.71.5`
- **Domain (defanged):** `progamevl.ru`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1053.005** — Persistence (article-specific)
- **T1485** — Data Destruction
- **T1570** — Lateral Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090.001** — Proxy: Internal Proxy
- **T1572** — Protocol Tunneling
- **T1105** — Ingress Tool Transfer
- **T1490** — Inhibit System Recovery
- **T1529** — System Shutdown/Reboot
- **T1491.001** — Defacement: Internal Defacement

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DynoWiper drop in C:\inetpub\pub\ — schtask.exe / *_update.exe execution

`UC_218_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_path="C:\\inetpub\\pub\\*" OR Processes.process="*\\inetpub\\pub\\schtask.exe*" OR Processes.process="*\\inetpub\\pub\\schtask2.exe*" OR Processes.process="*\\inetpub\\pub\\*_update.exe*") AND Processes.process_name!="schtasks.exe" by host Processes.process_name Processes.process_path Processes.user Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// DynoWiper staging/execution from C:\inetpub\pub\ — schtask.exe (note: legit binary is schtasks.exe), schtask2.exe, *_update.exe
let WindowDays = 30d;
(union isfuzzy=true
    (DeviceProcessEvents
        | where Timestamp > ago(WindowDays)
        | where FolderPath startswith @"C:\inetpub\pub\"
            or InitiatingProcessFolderPath startswith @"C:\inetpub\pub\"
        | where FileName in~ ("schtask.exe","schtask2.exe")
            or FileName endswith "_update.exe"
            or InitiatingProcessFileName in~ ("schtask.exe","schtask2.exe")
        | extend Source = "DeviceProcessEvents"
        | project Timestamp, DeviceName, AccountName, Source, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
    (DeviceFileEvents
        | where Timestamp > ago(WindowDays)
        | where FolderPath startswith @"C:\inetpub\pub\"
        | where ActionType in ("FileCreated","FileRenamed","FileModified")
        | where FileName in~ ("schtask.exe","schtask2.exe") or FileName endswith "_update.exe"
        | extend Source = "DeviceFileEvents"
        | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source, FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine))
| order by Timestamp desc
```

### [LLM] rsocx reverse SOCKS5 to 31.172.71.5:8008 (Sandworm Polish energy intrusion)

`UC_218_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_path="*\\Downloads\\r.exe" AND Processes.process="*-r *") OR (Processes.process="*-r 31.172.71.5:8008*") OR (Processes.process="*31.172.71.5:8008*") by host Processes.user Processes.process_name Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports values(All_Traffic.app) as proc from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="31.172.71.5" by host All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// rsocx reverse SOCKS5 proxy: r.exe -r 31.172.71.5:8008 + outbound to that IP
let C2_IP = "31.172.71.5";
let C2_Port = 8008;
let C2_Domain = "progamevl.ru";
let WindowDays = 30d;
(union isfuzzy=true
    (DeviceProcessEvents
        | where Timestamp > ago(WindowDays)
        | where (FileName =~ "r.exe" and InitiatingProcessFolderPath has @"\Downloads\")
            or FolderPath endswith @"\Downloads\r.exe"
            or ProcessCommandLine has C2_IP
            or ProcessCommandLine matches regex @"(?i)\\r\.exe\s+-r\s+\d{1,3}(\.\d{1,3}){3}:\d+"
        | extend Source = "Process"
        | project Timestamp, DeviceName, AccountName, Source, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256),
    (DeviceNetworkEvents
        | where Timestamp > ago(WindowDays)
        | where RemoteIP == C2_IP or (RemoteUrl has C2_Domain)
        | extend Source = "Network"
        | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source, FileName=InitiatingProcessFileName, FolderPath=InitiatingProcessFolderPath, ProcessCommandLine=InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl),
    (DeviceEvents
        | where Timestamp > ago(WindowDays)
        | where ActionType == "DnsQueryResponse"
        | extend Q = tostring(parse_json(AdditionalFields).QueryName)
        | where Q has C2_Domain
        | extend Source = "DNS"
        | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source, FileName=InitiatingProcessFileName, ProcessCommandLine=InitiatingProcessCommandLine, RemoteUrl=Q))
| order by Timestamp desc
```

### [LLM] ZOV wiper post-wipe shell command + LocWall.jpg wallpaper drop (Sandworm)

`UC_218_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe") AND ( (Processes.process="*rmdir C:\\\\ /s /q*" AND Processes.process="*shutdown /r*") OR (Processes.process="*time /t*" AND Processes.process="*ver*" AND Processes.process="*rmdir*" AND Processes.process="*shutdown*") ) by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | append [ | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.file_name="LocWall.jpg" AND Filesystem.file_path="*\\AppData\\Roaming\\LocWall.jpg" by host Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// ZOV wiper finishing chain: post-wipe shell command + LocWall.jpg wallpaper drop
let WindowDays = 30d;
(union isfuzzy=true
    (DeviceProcessEvents
        | where Timestamp > ago(WindowDays)
        | where InitiatingProcessFileName !endswith "$"
        | where ProcessCommandLine has "rmdir" and ProcessCommandLine has @"C:\" and ProcessCommandLine has "/s" and ProcessCommandLine has "/q"
            and ProcessCommandLine has "shutdown" and ProcessCommandLine has "/r"
            and ProcessCommandLine has_any ("time /t","ver "," ver&","& ver")
        | extend Source = "WiperShellCmd"
        | project Timestamp, DeviceName, AccountName, Source, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256),
    (DeviceFileEvents
        | where Timestamp > ago(WindowDays)
        | where ActionType in ("FileCreated","FileModified")
        | where FileName =~ "LocWall.jpg"
        | where FolderPath has @"\AppData\Roaming\" or FolderPath endswith @"\Roaming"
        | extend Source = "WallpaperDrop"
        | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
    (DeviceRegistryEvents
        | where Timestamp > ago(WindowDays)
        | where RegistryKey has @"\Control Panel\Desktop" and RegistryValueName =~ "Wallpaper"
        | where RegistryValueData has "LocWall.jpg"
        | extend Source = "WallpaperRegistry"
        | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source, FileName=InitiatingProcessFileName, FolderPath=InitiatingProcessFolderPath, SHA256=InitiatingProcessSHA256, RegistryKey, RegistryValueData))
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

### Article-specific behavioural hunt — DynoWiper update: Technical analysis and attribution

`UC_218_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — DynoWiper update: Technical analysis and attribution ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("schtask.exe","schtask2.exe","_update.exe","rubeus.exe","tmp_backup.tmp.exe","ts_5wb.tmp.exe","rsocx.exe") OR Processes.process_path="*C:\inetpub\pub\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\inetpub\pub\*" OR Filesystem.file_name IN ("schtask.exe","schtask2.exe","_update.exe","rubeus.exe","tmp_backup.tmp.exe","ts_5wb.tmp.exe","rsocx.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — DynoWiper update: Technical analysis and attribution
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("schtask.exe", "schtask2.exe", "_update.exe", "rubeus.exe", "tmp_backup.tmp.exe", "ts_5wb.tmp.exe", "rsocx.exe") or FolderPath has_any ("C:\inetpub\pub\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\inetpub\pub\") or FileName in~ ("schtask.exe", "schtask2.exe", "_update.exe", "rubeus.exe", "tmp_backup.tmp.exe", "ts_5wb.tmp.exe", "rsocx.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `31.172.71.5`, `progamevl.ru`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
