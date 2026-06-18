# [CRIT] Crypto Clipper uses Tor and worm-like propagation for persistence and control

**Source:** Microsoft Security Blog
**Published:** 2026-06-17
**Article:** https://www.microsoft.com/en-us/security/blog/2026/06/17/crypto-clipper-uses-tor-worm-like-propagation-for-persistence-control/

## Threat Profile

Content types 
Research 
Products and services 
Microsoft Defender 
Microsoft Defender Experts for XDR 
Topics 
Actionable threat insights 
Microsoft Threat Intelligence and Microsoft Defender Experts identified a Windows-based cryptocurrency clipper that has affected users since February of 2026. Clipper malware relies on stealing clipboard data and parsing it for valuable assets.
The clipper in this campaign relies on Windows Script Host and ActiveX-driven logic to launch a bundled Tor proxy a…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c`
- **SHA256:** `a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630`
- **SHA256:** `23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43`
- **SHA256:** `cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30`
- **SHA256:** `100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1090.003** — Multi-hop Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1564.003** — Hide Artifacts: Hidden Window
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1204.002** — User Execution: Malicious File
- **T1091** — Replication Through Removable Media
- **T1547.009** — Boot or Logon Autostart Execution: Shortcut Modification
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1105** — Ingress Tool Transfer
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Curl with SOCKS5 proxy to .onion C2 (Tor-tunneled exfil)

`UC_3_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=curl.exe Processes.process="*--socks5-hostname*" Processes.process="*.onion*" by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "curl.exe"
| where ProcessCommandLine has_all ("--socks5-hostname", ".onion")
   or ProcessCommandLine has_all ("--socks5-hostname", "localhost:9050")
   or ProcessCommandLine has_all ("--socks5-hostname", "127.0.0.1:9050")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Renamed Tor binary 'ugate.exe' execution (Crypto Clipper bundled proxy)

`UC_3_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=ugate.exe by Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let TorBinary = DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "ugate.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessId, DeviceId;
TorBinary
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where LocalPort == 9050 or RemotePort == 9050
    | project NetTime = Timestamp, DeviceId, InitiatingProcessFileName, LocalPort, RemotePort, RemoteIP
) on DeviceId
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, NetTime, LocalPort, RemotePort, RemoteIP
| order by Timestamp desc
```

### Scheduled task created with 5-6 char name + XML in Public\Documents (worm + clipper persistence)

`UC_3_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe Processes.process="*\/create*" Processes.process="*\/xml*" Processes.process="*C:\\Users\\Public\\Documents\\*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | regex process="(?i)schtasks\s+/create\s+/tn\s+[a-z]{4,6}\s+/xml\s+C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{4,6}\\\\[a-z]{4,6}\.xml" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine matches regex @"(?i)schtasks\s+/create\s+/tn\s+[a-z]{4,6}\s+/xml\s+C:\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.xml\s+/f"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Defender AV exclusion added for C:\Users\Public\Documents staging path

`UC_3_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe OR Processes.process_name=cmd.exe) (Processes.process="*Add-MpPreference*ExclusionPath*" OR Processes.process="*Set-MpPreference*ExclusionPath*" OR Processes.process="*Add-MpPreference*ExclusionProcess*") Processes.process="*Public\\Documents*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wmic.exe")
    | where ProcessCommandLine has_any ("Add-MpPreference","Set-MpPreference")
      and ProcessCommandLine has_any ("ExclusionPath","ExclusionProcess","ExclusionExtension")
      and (ProcessCommandLine has "Public\\Documents" or ProcessCommandLine has "Users\\Public")
    | project Timestamp, DeviceName, AccountName, Source="Process", Action=ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
),
(
    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where RegistryKey has @"\Windows Defender\Exclusions\"
    | where RegistryValueName has_any ("Public\\Documents","Users\\Public")
       or RegistryValueData has_any ("Public\\Documents","Users\\Public")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="Registry", Action=strcat(RegistryKey," :: ",RegistryValueName," = ",RegistryValueData), InitiatingProcessFileName, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### WScript/CScript executing JS payload from C:\Users\Public\Documents\<5-char> folder

`UC_3_9` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name=wscript.exe OR Processes.process_name=cscript.exe) Processes.process="*C:\\Users\\Public\\Documents\\*" by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | regex process="(?i)C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{4,6}\\\\[a-z]{4,6}\.(js|jse|vbs|wsf)" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine matches regex @"(?i)C:\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.(js|jse|vbs|wsf)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Crypto Clipper Worm SHA-256 IOC hit (MS-published hashes)

`UC_3_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c","a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630","23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43","cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30","100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let WormHashes = dynamic(["7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c","a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630","23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43","cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30","100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8"]);
union
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (WormHashes)
    | project Timestamp, DeviceName, AccountName, Source="Process", FileName, FolderPath, ProcessCommandLine, SHA256
),
(
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (WormHashes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="FileDrop", FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA256
),
(
    DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (WormHashes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="ImageLoad", FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA256
)
| order by Timestamp desc
```

### USB-borne worm: bulk .lnk creation mirroring legitimate document filenames

`UC_3_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Filesystem.file_name) as files_created dc(Filesystem.file_name) as unique_lnk min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="*.lnk" (Filesystem.file_path="D:\\*" OR Filesystem.file_path="E:\\*" OR Filesystem.file_path="F:\\*" OR Filesystem.file_path="G:\\*" OR Filesystem.file_path="H:\\*") by Filesystem.dest Filesystem.process_name Filesystem.user span=5m | `drop_dm_object_name(Filesystem)` | where unique_lnk >= 3 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let RemovableRoots = dynamic(["D:\\","E:\\","F:\\","G:\\","H:\\","I:\\","J:\\"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".lnk"
| where FolderPath has_any (RemovableRoots)
| summarize LnkCount = dcount(FileName), SampleLnks = make_set(FileName, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, bin(Timestamp, 5m)
| where LnkCount >= 3
| order by FirstSeen desc
```

### Crypto Clipper backdoor: cfile drop under Public\Documents followed by wscript EVAL chain

`UC_3_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name=cfile Filesystem.file_path="C:\\Users\\Public\\Documents\\*" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path _time | `drop_dm_object_name(Filesystem)`
| rename _time as cfile_time
| join type=inner dest [
    | tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.parent_process_name=wscript.exe (Processes.process_name=cmd.exe OR Processes.process_name=powershell.exe OR Processes.process_name=cscript.exe OR Processes.process_name=mshta.exe) by Processes.dest Processes.process Processes.parent_process _time
    | `drop_dm_object_name(Processes)`
    | rename _time as child_time
  ]
| where child_time >= cfile_time AND child_time <= (cfile_time + 600)
| eval delay_sec=child_time-cfile_time
| table cfile_time, child_time, delay_sec, dest, user, file_path, parent_process, process
```

**Defender KQL:**
```kql
let CfileWrites = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileCreated"
    | where FileName =~ "cfile"
    | where FolderPath startswith @"C:\Users\Public\Documents\"
    | project CfileTime = Timestamp, DeviceId, DeviceName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName;
let ScriptChildren = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "wscript.exe"
    | where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","cscript.exe","mshta.exe","rundll32.exe")
    | project ChildTime = Timestamp, DeviceId, ChildFileName = FileName, ChildCmd = ProcessCommandLine, InitCmd = InitiatingProcessCommandLine;
CfileWrites
| join kind=inner ScriptChildren on DeviceId
| where ChildTime between (CfileTime .. CfileTime + 10m)
| project CfileTime, ChildTime, DelaySec = datetime_diff('second', ChildTime, CfileTime), DeviceName, FolderPath, InitCmd, ChildFileName, ChildCmd
| order by CfileTime desc
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

### Article-specific behavioural hunt — Crypto Clipper uses Tor and worm-like propagation for persistence and control

`UC_3_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Crypto Clipper uses Tor and worm-like propagation for persistence and control ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("ugate.exe","curl.exe") OR Processes.process_path="*C:\Users\Public\Documents*" OR Processes.process_path="*C:\Users\Public\Documents\omoho*" OR Processes.process_path="*C:\Users\Public\Documents\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Public\Documents*" OR Filesystem.file_path="*C:\Users\Public\Documents\omoho*" OR Filesystem.file_path="*C:\Users\Public\Documents\*" OR Filesystem.file_name IN ("ugate.exe","curl.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Crypto Clipper uses Tor and worm-like propagation for persistence and control
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("ugate.exe", "curl.exe") or FolderPath has_any ("C:\Users\Public\Documents", "C:\Users\Public\Documents\omoho", "C:\Users\Public\Documents\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Public\Documents", "C:\Users\Public\Documents\omoho", "C:\Users\Public\Documents\") or FileName in~ ("ugate.exe", "curl.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `7630debd35cac6b7d58c4427695579b3e3a8b1cc462f523234cd6c698882a68c`, `a7abf1d9d6686af1cefcd60b17a312e7eb8cfe267def1ec34aeab6128c811630`, `23c1e673f315dafa14b73034a90dd3d393a984451ff6601b8be8142be6487b43`, `cf9fc891ea5ca5ecd8113ef3e69f6f52ff538b6cccbdaa9559106fc72bc6da30`, `100407796028bf3649752d9d2a67a0e4394d752eb8de86daa42920e814f3fae8`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
