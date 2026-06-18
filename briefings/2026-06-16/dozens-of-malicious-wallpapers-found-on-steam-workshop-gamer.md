# [CRIT] Dozens of malicious wallpapers found on Steam Workshop: gamers’ accounts at risk

**Source:** Securelist (Kaspersky)
**Published:** 2026-06-16
**Article:** https://securelist.com/dozens-of-malicious-wallpapers-found-on-steam-workshop/120186/

## Threat Profile

Table of Contents
What is Wallpaper Engine? 
Application wallpapers: a built-in security risk 
Inside an infected game wallpaper 
Attribution and victims 
How to stay safe 
Indicators of compromise 
Authors
Maxim Starodubov 
Denis Brylev 
Since late 2025, malware has been spreading rapidly through the Steam Workshop, the gaming platform’s built-in service for players to create and share custom content. The attackers are primarily targeting gamers in China and Russia, aiming to hijack their accou…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `202.144.192.29`
- **IPv4 (defanged):** `120.48.156.17`
- **Domain (defanged):** `brightly.to`
- **MD5:** `95856f2ce428c728d9781d3296558068`
- **MD5:** `af080780cca2acd1d082ce01e7cc346a`
- **MD5:** `c133c3dd9f7d6934598025047df41abf`
- **MD5:** `d1693bbff456ae8fa3360446706df6da`
- **MD5:** `8c2cc585ad8a13a72a704c0fda0c9854`
- **MD5:** `b9fa763a53da3eea742d0f3c845a8c09`
- **MD5:** `ded08ae5df7f1b12e5fdb767dbbed0b1`
- **MD5:** `20965254e29104986e11939decd39549`
- **MD5:** `18dedc0009f0927cba6425c84cce9883`
- **MD5:** `0f4f01c6d495abb37403072dd017ce8d`
- **MD5:** `5620f01284329f561b1839a36be55355`
- **MD5:** `fe1f6485013cd5e6d5cf718049b0b8d6`
- **MD5:** `74414ed4b63aadec039b603c32762b80`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1105** — Ingress Tool Transfer
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1574.001** — Hijack Execution Flow: DLL Search Order Hijacking
- **T1528** — Steal Application Access Token
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Wallpaper Engine spawns shell / scripting child from Steam Workshop content

`UC_101_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_hash) as process_hash from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("wallpaper32.exe","wallpaper64.exe","wallpaperservice32_c.exe","wallpaperservice64_c.exe")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe") OR Processes.process_path="*\\steamapps\\workshop\\content\\431960\\*" OR Processes.process_path="*\\steamapps\\common\\wallpaper_engine\\projects\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wallpaper32.exe","wallpaper64.exe","wallpaperservice32_c.exe","wallpaperservice64_c.exe")
| where AccountName !endswith "$"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
   or FolderPath has_any (@"\steamapps\workshop\content\431960\", @"\steamapps\common\wallpaper_engine\projects\")
   or FileName =~ "._cache_GAME1.exe"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256, MD5
| order by Timestamp desc
```

### DarkKomet 'Synaptics.exe' dropped outside the legitimate Synaptics install path

`UC_101_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_name="Synaptics.exe" AND Filesystem.action="created" AND NOT (Filesystem.file_path IN ("*\\Program Files\\Synaptics\\*","*\\Program Files (x86)\\Synaptics\\*","*\\Windows\\System32\\DriverStore\\*")) by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "Synaptics.exe"
| where FolderPath !has @"\Program Files\Synaptics\"
   and FolderPath !has @"\Program Files (x86)\Synaptics\"
   and FolderPath !has @"\Windows\System32\DriverStore\"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### `._cache_GAME1.exe` execution — Wallpaper Engine staged dropper

`UC_101_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_path) as process_path values(Processes.process_hash) as process_hash values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="._cache_GAME1.exe" OR Processes.process="*._cache_GAME1.exe*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let procs = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "._cache_GAME1.exe" or ProcessCommandLine has "._cache_GAME1.exe"
    | project Timestamp, DeviceId, DeviceName, AccountName,
              ChildImage = FolderPath, ChildCmd = ProcessCommandLine, ChildSHA256 = SHA256,
              ParentImage = InitiatingProcessFileName,
              ParentPath  = InitiatingProcessFolderPath,
              ParentCmd   = InitiatingProcessCommandLine;
let files = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "._cache_GAME1.exe"
    | project Timestamp, DeviceId, DeviceName, ActionType, FolderPath, FileName, SHA256, MD5,
              InitiatingProcessFileName, InitiatingProcessCommandLine;
union procs, files
| order by Timestamp desc
```

### `AggregatorHost.dll` loaded from outside System32 — Steam-session-theft DLL

`UC_101_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as creator from datamodel=Endpoint.Filesystem where Filesystem.file_name="AggregatorHost.dll" AND NOT (Filesystem.file_path IN ("*\\Windows\\System32\\*","*\\Windows\\SysWOW64\\*","*\\Windows\\WinSxS\\*","*\\dotnet\\*")) by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let suspicious_writes = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified")
    | where FileName =~ "AggregatorHost.dll"
    | where FolderPath !has @"\Windows\System32\"
        and FolderPath !has @"\Windows\SysWOW64\"
        and FolderPath !has @"\Windows\WinSxS\"
        and FolderPath !has @"\dotnet\"
    | project Timestamp, DeviceId, DeviceName, EventKind="FileWrite",
              Path = FolderPath, SHA256, MD5,
              Writer = InitiatingProcessFileName, WriterCmd = InitiatingProcessCommandLine;
let suspicious_loads = DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "AggregatorHost.dll"
    | where FolderPath !has @"\Windows\System32\"
        and FolderPath !has @"\Windows\SysWOW64\"
        and FolderPath !has @"\Windows\WinSxS\"
        and FolderPath !has @"\dotnet\"
    | project Timestamp, DeviceId, DeviceName, EventKind="ImageLoad",
              Path = FolderPath, SHA256, MD5,
              Writer = InitiatingProcessFileName, WriterCmd = InitiatingProcessCommandLine;
union suspicious_writes, suspicious_loads
| order by Timestamp desc
```

### Outbound C2 to Steam Workshop wallpaper campaign endpoints (120.48.156.17 / 202.144.192.29)

`UC_101_12` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.src) as src from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("120.48.156.17","202.144.192.29")) by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| append [| tstats `summariesonly` count from datamodel=Web.Web where (Web.url="*://120.48.156.17/ey.php*" OR Web.url="*://202.144.192.29/audit.php*" OR Web.url="*/download2/Themes2.zip*") by Web.src Web.dest Web.url Web.http_method | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("120.48.156.17","202.144.192.29")
   or RemoteUrl has_any ("/ey.php","/audit.php","/download2/Themes2.zip")
| project Timestamp, DeviceName, ActionType,
          ProcImage = InitiatingProcessFileName,
          ProcCmd   = InitiatingProcessCommandLine,
          ProcPath  = InitiatingProcessFolderPath,
          ProcSHA256= InitiatingProcessSHA256,
          ParentImage = InitiatingProcessParentFileName,
          RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### Persistence: Run-key / scheduled task referencing Wallpaper Engine workshop paths or campaign binaries

`UC_101_13` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_path) as registry_path values(Registry.registry_value_data) as registry_value_data values(Registry.process_name) as writer from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentVersion\\Run*" OR Registry.registry_path="*\\CurrentVersion\\RunOnce*" OR Registry.registry_path="*\\Winlogon\\Shell*" OR Registry.registry_path="*\\Winlogon\\Userinit*") AND (Registry.registry_value_data="*\\steamapps\\workshop\\content\\431960\\*" OR Registry.registry_value_data="*\\steamapps\\common\\wallpaper_engine\\projects\\*" OR Registry.registry_value_data="*Synaptics.exe*" OR Registry.registry_value_data="*._cache_GAME1.exe*" OR Registry.registry_value_data="*AggregatorHost.dll*") by Registry.dest Registry.user Registry.registry_key_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let bad_strings = dynamic([@"\steamapps\workshop\content\431960\", @"\steamapps\common\wallpaper_engine\projects\", "Synaptics.exe", "._cache_GAME1.exe", "AggregatorHost.dll"]);
let reg = DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Winlogon\Shell", @"\Winlogon\Userinit", @"\Image File Execution Options\")
    | where RegistryValueData has_any (bad_strings)
    | project Timestamp, DeviceName, ActionType, EventKind="RegRunKey",
              RegistryKey, RegistryValueName, RegistryValueData,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName;
let tasks = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "ScheduledTaskCreated"
    | where AdditionalFields has_any (bad_strings) or ProcessCommandLine has_any (bad_strings)
    | project Timestamp, DeviceName, EventKind="SchedTask",
              ProcessCommandLine, AdditionalFields,
              InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName;
union reg, tasks
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

### Article-specific behavioural hunt — Dozens of malicious wallpapers found on Steam Workshop: gamers’ accounts at risk

`UC_101_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Dozens of malicious wallpapers found on Steam Workshop: gamers’ accounts at risk ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("synaptics.exe","._cache_game1.exe","aggregatorhost.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("synaptics.exe","._cache_game1.exe","aggregatorhost.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Dozens of malicious wallpapers found on Steam Workshop: gamers’ accounts at risk
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("synaptics.exe", "._cache_game1.exe", "aggregatorhost.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("synaptics.exe", "._cache_game1.exe", "aggregatorhost.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `202.144.192.29`, `120.48.156.17`, `brightly.to`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `95856f2ce428c728d9781d3296558068`, `af080780cca2acd1d082ce01e7cc346a`, `c133c3dd9f7d6934598025047df41abf`, `d1693bbff456ae8fa3360446706df6da`, `8c2cc585ad8a13a72a704c0fda0c9854`, `b9fa763a53da3eea742d0f3c845a8c09`, `ded08ae5df7f1b12e5fdb767dbbed0b1`, `20965254e29104986e11939decd39549` _(+5 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
