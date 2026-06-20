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
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1547** — Boot or Logon Autostart Execution
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1572** — Protocol Tunneling
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1218** — System Binary Proxy Execution
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1112** — Modify Registry
- **T1105** — Ingress Tool Transfer
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CryptoBandits scheduled task creation via XML import to Public\Documents 5-char staging folder

`UC_75_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe Processes.process="*\\Users\\Public\\Documents\\*" Processes.process="*/create*" Processes.process="*/xml*" by host Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| rex field=process "(?i)/tn\s+(?<task_name>[a-z]{4,6})\s+/xml\s+(?<xml_path>C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{4,6}\\\\[a-z]{4,6}\.xml)"
| where isnotnull(task_name) AND isnotnull(xml_path)
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine matches regex @"(?i)schtasks\s+/create\s+/tn\s+[a-z]{4,6}\s+/xml\s+C:\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.xml\s+/f"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Curl over Tor SOCKS5 proxy at localhost:9050 to .onion C2

`UC_75_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=curl.exe Processes.process="*--socks5-hostname*" Processes.process="*localhost:9050*" Processes.process="*.onion*" by host Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "curl.exe"
| where ProcessCommandLine has_all ("--socks5-hostname", "localhost:9050", ".onion")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### WScript or CScript executing JavaScript payload from Public\Documents 5-char staging folder

`UC_75_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN (wscript.exe, cscript.exe) Processes.process="*\\Users\\Public\\Documents\\*" Processes.process="*.js*" by host Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| rex field=process "(?i)(?<js_path>C:\\\\Users\\\\Public\\\\Documents\\\\[a-z]{4,6}\\\\[a-z]{4,6}\.js)"
| where isnotnull(js_path)
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine matches regex @"(?i)C:\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.js"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Renamed Tor client running as ugate.exe (CryptoBandits bundled proxy)

`UC_75_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_path) as paths values(Processes.process_hash) as hashes from datamodel=Endpoint.Processes where Processes.process_name=ugate.exe by host Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "ugate.exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Defender exclusion path added for Public\Documents staging folder (worm self-protection)

`UC_75_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN (powershell.exe, pwsh.exe) (Processes.process="*Add-MpPreference*" OR Processes.process="*Set-MpPreference*") Processes.process="*ExclusionPath*" Processes.process="*Public\\Documents*" by host Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
let ExclusionByPS = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("Add-MpPreference", "Set-MpPreference")
| where ProcessCommandLine has "ExclusionPath"
| where ProcessCommandLine has @"Public\Documents"
| project Timestamp, DeviceName, AccountName, Source = "PowerShell", Detail = ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let ExclusionByRegistry = DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\Microsoft\Windows Defender\Exclusions\Paths"
| where RegistryValueName has @"\Users\Public\Documents\"
   or RegistryValueData has @"\Users\Public\Documents\"
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Source = "Registry", Detail = strcat(RegistryValueName, " = ", RegistryValueData), InitiatingProcessFileName, InitiatingProcessCommandLine;
union ExclusionByPS, ExclusionByRegistry
| order by Timestamp desc
```

### CryptoBandits cfile payload artifact created under Public\Documents

`UC_75_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_name="cfile" Filesystem.file_path="*\\Users\\Public\\Documents\\*" Filesystem.action=created by host Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName =~ "cfile"
| where FolderPath has @"\Users\Public\Documents\"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### WScript or CScript with Public\Documents JS spawning curl, schtasks, cmd, or PowerShell child

`UC_75_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN (wscript.exe, cscript.exe) Processes.parent_process="*\\Users\\Public\\Documents\\*.js*" Processes.process_name IN (curl.exe, schtasks.exe, cmd.exe, powershell.exe, pwsh.exe) by host Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
| where InitiatingProcessCommandLine has @"\Users\Public\Documents\"
| where InitiatingProcessCommandLine has ".js"
| where FileName in~ ("curl.exe", "schtasks.exe", "cmd.exe", "powershell.exe", "pwsh.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
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

`UC_75_4` · phase: **exploit** · confidence: **High**

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
