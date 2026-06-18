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
- **T1036.005** — Match Legitimate Name or Location
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1218** — System Binary Proxy Execution
- **T1091** — Replication Through Removable Media
- **T1547.009** — Shortcut Modification
- **T1518.001** — Security Software Discovery
- **T1047** — Windows Management Instrumentation
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
- **T1090.001** — Internal Proxy
- **T1547.001** — Registry Run Keys / Startup Folder

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Renamed Tor binary 'ugate.exe' launched by WScript with hidden window

`UC_18_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="ugate.exe" OR (Processes.parent_process_name IN ("wscript.exe","cscript.exe") AND Processes.process="*ugate.exe*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | where like(process_path,"%\\Users\\Public\\Documents\\%") OR match(process,"(?i)ugate\.exe")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "ugate.exe"
   or (InitiatingProcessFileName in~ ("wscript.exe","cscript.exe") and ProcessCommandLine has "ugate.exe")
| where FolderPath has @"\Users\Public\Documents\" or InitiatingProcessFolderPath has @"\Users\Public\Documents\"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### curl SOCKS5 to localhost:9050 .onion C2 beacon

`UC_18_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="curl.exe" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process,"(?i)--socks5-hostname") AND match(process,"(?i)(localhost|127\.0\.0\.1):9050") AND match(process,"(?i)\.onion")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "curl.exe"
| where ProcessCommandLine has_all ("--socks5-hostname", ":9050", ".onion")
   or (ProcessCommandLine has "--socks5-hostname" and ProcessCommandLine has_any ("localhost:9050","127.0.0.1:9050"))
| extend Endpoint = case(
    ProcessCommandLine has "/route.php", "beacon",
    ProcessCommandLine has "/recvf.php", "screenshot-upload",
    ProcessCommandLine has "/stub.php",  "payload-download",
    "other")
| project Timestamp, DeviceName, AccountName, Endpoint, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Worm scheduled-task created from Public\Documents 5-char staging folder

`UC_18_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process,"(?i)schtasks\s+/create\s+/tn\s+[a-z]{4,6}\s+/xml\s+C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{4,6}\\\\[a-z]{4,6}\.xml\s+/f")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine matches regex @"(?i)schtasks\s+/create\s+/tn\s+[a-z]{4,6}\s+/xml\s+C:\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.xml\s+/f"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Defender AV folder/path exclusion targeting Public\Documents staging

`UC_18_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*Add-MpPreference*ExclusionPath*","*Add-MpPreference*ExclusionProcess*") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process,"(?i)(Users\\\\Public\\\\Documents|wscript|cscript|curl|ugate)")
```

**Defender KQL:**
```kql
union
(DeviceProcessEvents
  | where Timestamp > ago(7d)
  | where FileName in~ ("powershell.exe","pwsh.exe")
  | where ProcessCommandLine has "Add-MpPreference"
  | where ProcessCommandLine has_any (@"\Users\Public\Documents\", "wscript.exe", "cscript.exe", "curl.exe", "ugate.exe")
  | project Timestamp, DeviceName, AccountName, Source="PSExclusion", ProcessCommandLine, InitiatingProcessFileName),
(DeviceEvents
  | where Timestamp > ago(7d)
  | where ActionType in ("AntivirusExclusionUpdated","AsrPathExclusionAdded")
  | where AdditionalFields has_any (@"\Users\Public\Documents\", "wscript.exe", "cscript.exe", "curl.exe", "ugate.exe")
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source=ActionType, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName)
| order by Timestamp desc
```

### WScript/CScript executing JS from Public\Documents 5-char folder

`UC_18_9` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.process_path | `drop_dm_object_name(Processes)` | where match(process,"(?i)C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{4,6}\\\\[a-z]{4,6}\.js")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine matches regex @"(?i)C:\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.js"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### USB-borne .lnk worm: shortcut files mass-created on removable media

`UC_18_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_name) as files dc(Filesystem.file_name) as distinct_lnk from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="*.lnk" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name _time span=5m | `drop_dm_object_name(Filesystem)` | where distinct_lnk >= 5 AND NOT match(file_path,"(?i)\\\\(Programs|Recent|Start Menu)\\\\")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".lnk"
| where FolderPath !has @"\Programs\" and FolderPath !has @"\Recent\" and FolderPath !has @"\Start Menu\" and FolderPath !has @"\Roaming\Microsoft\Office\"
| where InitiatingProcessFileName !in~ ("explorer.exe","msiexec.exe","setup.exe")
| summarize LnkCount = dcount(FileName), Sample = make_set(FileName,10), Folders = make_set(FolderPath,5) by DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, 5m)
| where LnkCount >= 5
| order by Timestamp desc
```

### WMI Win32_Process query used as Task Manager anti-analysis gate

`UC_18_11` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe","cscript.exe") Processes.process_name="wmic.exe" by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where match(process,"(?i)(Win32_Process|process\s+get)") AND match(parent_process,"(?i)C:\\\\Users\\\\Public\\\\Documents\\\\")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where InitiatingProcessCommandLine has @"\Users\Public\Documents\"
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_any ("Win32_Process","process get","process where")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Beacon/screenshot/payload C2 endpoint requested via Tor SOCKS5

`UC_18_12` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="curl.exe" Processes.process IN ("*route.php*","*recvf.php*","*stub.php*") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | eval action=case(match(process,"(?i)route\.php"),"beacon",match(process,"(?i)recvf\.php"),"screenshot-upload",match(process,"(?i)stub\.php"),"payload-download") | where match(process,"(?i)\.onion")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "curl.exe"
| where ProcessCommandLine has ".onion"
| where ProcessCommandLine has_any ("/route.php","/recvf.php","/stub.php")
| extend Action = case(
    ProcessCommandLine has "/route.php", "beacon-or-EVAL",
    ProcessCommandLine has "/recvf.php", "screenshot-exfil",
    ProcessCommandLine has "/stub.php",  "payload-download",
    "other")
| project Timestamp, DeviceName, AccountName, Action, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 'cfile' EVAL backdoor payload dropped by script interpreter

`UC_18_13` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="cfile" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process | `drop_dm_object_name(Filesystem)` | where match(process_name,"(?i)(wscript|cscript|curl)\.exe")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName =~ "cfile"
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","curl.exe","ugate.exe")
   or FolderPath has @"\Users\Public\Documents\"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Loopback connection to 127.0.0.1:9050 from non-Tor process

`UC_18_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_ip="127.0.0.1" All_Traffic.dest_port=9050 by All_Traffic.src_ip All_Traffic.process_name All_Traffic.process | `drop_dm_object_name(All_Traffic)` | where NOT match(process_name,"(?i)^(tor|tor-browser|firefox)\.exe$")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ConnectionSuccess"
| where RemoteIP in ("127.0.0.1","::1") and RemotePort == 9050
| where InitiatingProcessFileName !in~ ("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by Timestamp desc
```

### Run-key autostart written by WScript from Public Documents staging

`UC_18_15` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentVersion\\Run*" OR Registry.registry_path="*\\CurrentVersion\\RunOnce*") by Registry.dest Registry.user Registry.process_name Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | where match(registry_value_data,"(?i)(C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{4,6}|ugate\.exe|wscript.*\.js)") OR match(process_name,"(?i)(wscript|cscript)\.exe")
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where RegistryValueData has_any (@"\Users\Public\Documents\", "ugate.exe", ".js")
   or InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
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

`UC_18_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
