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
- **T1091** — Replication Through Removable Media
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1218** — System Binary Proxy Execution
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1090.001** — Proxy: Internal Proxy
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CryptoBandits USB worm — bulk .lnk creation on removable media by non-Explorer process

`UC_1_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Filesystem.file_name) as files from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="*.lnk" Filesystem.file_path="[D-Z]:\\*" by host Filesystem.process_name _time span=5m | `drop_dm_object_name(Filesystem)` | where count >= 5 AND NOT match(process_name, "(?i)(explorer|OneDrive|OneDriveStandaloneUpdater)\\.exe")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".lnk"
| where FolderPath matches regex @"^[D-Z]:\\"
| where InitiatingProcessFileName !in~ ("explorer.exe", "OneDrive.exe", "OneDriveStandaloneUpdater.exe", "SearchProtocolHost.exe")
| summarize LnkCount = dcount(FileName), Samples = make_set(FileName, 25), Folders = make_set(FolderPath, 10) by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, 5m)
| where LnkCount >= 5
| order by Timestamp desc
```

### WScript/CScript executing .js from Public\Documents 5-char staging folder

`UC_1_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") Processes.process="*\\Users\\Public\\Documents\\*" by host Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | where match(process, "(?i)C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{5}\\\\[a-z]{5}\\.js") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine matches regex @"(?i)C:\\Users\\Public\\Documents\\[a-z]{5}\\[a-z]{5}\.js"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### CryptoBandits scheduled task created from Public\Documents XML stub

`UC_1_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" Processes.process="*\\Users\\Public\\Documents\\*" Processes.process="*/xml*" Processes.process="*/create*" by host Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process, "(?i)/create\\s+/tn\\s+[a-z]{4,6}\\s+/xml\\s+C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{4,6}\\\\[a-z]{4,6}\\.xml") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine matches regex @"(?i)schtasks\s+/create\s+/tn\s+[a-z]{4,6}\s+/xml\s+C:\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.xml\s+/f"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### CryptoBandits Defender exclusions added for Public\Documents staging and ugate.exe

`UC_1_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe") (Processes.process="*Add-MpPreference*" OR Processes.process="*Set-MpPreference*") (Processes.process="*ExclusionPath*" OR Processes.process="*ExclusionProcess*" OR Processes.process="*ExclusionExtension*") (Processes.process="*Public\\Documents*" OR Processes.process="*ugate.exe*") by host Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Add-MpPreference", "Set-MpPreference")
| where ProcessCommandLine has_any ("ExclusionPath", "ExclusionProcess", "ExclusionExtension")
| where ProcessCommandLine has_any (@"Public\Documents", "ugate.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### curl with --socks5-hostname tunneling to localhost:9050 / .onion C2

`UC_1_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="curl.exe" Processes.process="*--socks5-hostname*" (Processes.process="*localhost:9050*" OR Processes.process="*.onion*") by host Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | eval has_c2_endpoint=if(match(process, "/route\\.php|/recvf\\.php|/stub\\.php"), 1, 0) | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "curl.exe"
| where ProcessCommandLine has "--socks5-hostname"
| where ProcessCommandLine has_any ("localhost:9050", "127.0.0.1:9050", ".onion")
| extend HasC2Endpoint = ProcessCommandLine has_any ("/route.php", "/recvf.php", "/stub.php")
| extend HasC2Action = ProcessCommandLine has_any ("GUID", "SEED", "PKEY", "REPL", "EVAL")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, HasC2Endpoint, HasC2Action, SHA256
| order by Timestamp desc
```

### Renamed Tor binary ugate.exe execution or as parent process

`UC_1_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_name="ugate.exe" OR Processes.parent_process_name="ugate.exe") by host Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` | append [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.original_file_name="tor.exe" Processes.process_name!="tor.exe" Processes.process_name!="torbrowser.exe" by host Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash | `drop_dm_object_name(Processes)` ]
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "ugate.exe"
   or InitiatingProcessFileName =~ "ugate.exe"
   or (ProcessVersionInfoProductName has "Tor" and FileName !in~ ("tor.exe", "torbrowser.exe", "firefox.exe"))
   or (ProcessVersionInfoOriginalFileName =~ "tor.exe" and FileName != "tor.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessVersionInfoProductName, ProcessVersionInfoOriginalFileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Script host spawning shell — possible CryptoBandits EVAL backdoor execution

`UC_1_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as proc_time from datamodel=Endpoint.Processes where (Processes.parent_process_name="wscript.exe" OR Processes.parent_process_name="cscript.exe") (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="mshta.exe" OR Processes.process_name="rundll32.exe" OR Processes.process_name="regsvr32.exe") by host Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | join type=inner host [ | tstats summariesonly=true min(_time) as net_time from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="127.0.0.1" All_Traffic.dest_port=9050 by All_Traffic.src ] | where proc_time >= net_time AND proc_time <= net_time + 600
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSeconds = 600;
let TorConn = DeviceNetworkEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "ConnectionSuccess"
    | where RemoteIP in ("127.0.0.1", "::1") and RemotePort == 9050
    | where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe", "curl.exe", "ugate.exe")
    | project NetTime = Timestamp, DeviceId, DeviceName, NetCallerName = InitiatingProcessFileName, NetCallerCmd = InitiatingProcessCommandLine;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "wmic.exe")
| join kind=inner TorConn on DeviceId
| where Timestamp between (NetTime .. NetTime + WindowSeconds * 1s)
| project Timestamp, NetTime, DelaySec = datetime_diff('second', Timestamp, NetTime), DeviceName, AccountName, NetCallerName, NetCallerCmd, ChildFile = FileName, ChildCmd = ProcessCommandLine, ParentCmd = InitiatingProcessCommandLine
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

`UC_1_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
