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
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1571** — Non-Standard Port
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1091** — Replication Through Removable Media
- **T1204.002** — User Execution: Malicious File
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1113** — Screen Capture

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CryptoBandits curl beacon over Tor SOCKS5 proxy to .onion C2

`UC_106_5` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="curl.exe" Processes.process="*--socks5-hostname*" Processes.process="*9050*" (Processes.process="*.onion*" OR Processes.process="*/route.php*" OR Processes.process="*/recvf.php*" OR Processes.process="*/stub.php*") by Processes.dest Processes.user Processes.parent_process_name Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "curl.exe"
| where ProcessCommandLine has "--socks5-hostname" and ProcessCommandLine has "9050"
| where ProcessCommandLine has_any (".onion", "/route.php", "/recvf.php", "/stub.php")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Renamed Tor binary ugate.exe / Tor masquerade launched on endpoint

`UC_106_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="ugate.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "ugate.exe"
   or (ProcessVersionInfoOriginalFileName =~ "tor.exe" and FileName !~ "tor.exe")
   or (ProcessVersionInfoProductName has "Tor" and FileName !~ "tor.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessVersionInfoOriginalFileName, ProcessVersionInfoProductName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Scheduled task created from JScript payload XML in Public\Documents staging folder

`UC_106_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" Processes.process="*/create*" Processes.process="*/xml*" Processes.process="*\\Users\\Public\\Documents\\*" by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | regex process="(?i)\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.xml" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create" and ProcessCommandLine has "/xml"
| where ProcessCommandLine matches regex @"(?i)\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.xml"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### WScript/CScript executing dropped JScript clipper from Public\Documents staging folder

`UC_106_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") Processes.process="*\\Users\\Public\\Documents\\*" Processes.process="*.js*" by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | regex process="(?i)\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.js" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("wscript.exe", "cscript.exe")
| where ProcessCommandLine matches regex @"(?i)\\Users\\Public\\Documents\\[a-z]{4,6}\\[a-z]{4,6}\.js"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Microsoft Defender exclusion added for clipper staging folder or script-host binaries

`UC_106_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Microsoft\\Windows Defender\\Exclusions*" (Registry.registry_value_name="*\\Users\\Public\\Documents\\*" OR Registry.registry_value_name="*wscript.exe*" OR Registry.registry_value_name="*cscript.exe*" OR Registry.registry_value_name="*ugate.exe*" OR Registry.registry_value_name="*curl.exe*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"\Microsoft\Windows Defender\Exclusions"
| where RegistryValueName has @"\Users\Public\Documents\"
   or RegistryValueName has_any ("wscript.exe", "cscript.exe", "ugate.exe", "curl.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### USB worm propagation: burst of .lnk shortcuts created by non-Explorer process

`UC_106_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count dc(Filesystem.file_path) as lnk_paths min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="*.lnk" NOT Filesystem.process_name IN ("explorer.exe","onedrive.exe","msiexec.exe","setup.exe") by Filesystem.dest Filesystem.process_name _time span=5m | `drop_dm_object_name(Filesystem)` | where lnk_paths >= 5 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName endswith ".lnk"
| where InitiatingProcessFileName !in~ ("explorer.exe", "onedrive.exe", "msiexec.exe", "setup.exe", "svchost.exe")
| summarize LnkFolders = dcount(FolderPath), SampleFolders = make_set(FolderPath, 10), SampleFiles = make_set(FileName, 10), FirstSeen = min(Timestamp), arg_max(Timestamp, *) by DeviceName, InitiatingProcessFileName, InitiatingProcessId, bin(Timestamp, 5m)
| where LnkFolders >= 5   // worm creates one .lnk per harvested document
| order by Timestamp desc
```

### Tor EVAL backdoor: script-host clipper spawning command interpreters

`UC_106_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="wscript.exe" OR Processes.parent_process_name="cscript.exe") Processes.parent_process="*\\Users\\Public\\Documents\\*" (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="curl.exe" OR Processes.process_name="mshta.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
| where InitiatingProcessCommandLine matches regex @"(?i)\\Users\\Public\\Documents\\[a-z]{4,6}\\"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "curl.exe", "mshta.exe", "cscript.exe", "wscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### PowerShell screen capture spawned by clipper script host (collection)

`UC_106_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe") Processes.process="*CopyFromScreen*" (Processes.parent_process_name="wscript.exe" OR Processes.parent_process_name="cscript.exe" OR Processes.parent_process="*\\Users\\Public\\Documents\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has "CopyFromScreen"
   or (ProcessCommandLine has "System.Drawing" and ProcessCommandLine has "Bitmap" and ProcessCommandLine has_any ("Graphics", "Screen"))
| where InitiatingProcessFileName in~ ("wscript.exe", "cscript.exe")
   or InitiatingProcessCommandLine has @"\Users\Public\Documents\"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
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

`UC_106_4` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
