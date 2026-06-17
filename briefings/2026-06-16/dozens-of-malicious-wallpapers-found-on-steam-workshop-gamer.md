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
- **T1036.005** — Match Legitimate Name or Location
- **T1204.002** — Malicious File
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1574.002** — DLL Side-Loading
- **T1204.001** — Malicious Link
- **T1059.001** — PowerShell
- **T1059.003** — Windows Command Shell
- **T1056.001** — Keylogging
- **T1555** — Credentials from Password Stores
- **T1005** — Data from Local System
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
- **T1053.005** — Scheduled Task
- **T1574.011** — Services Registry Permissions Weakness

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### DarkKomet 'Synaptics.exe' masquerade dropped by Wallpaper Engine workshop content

`UC_32_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.process_name="Synaptics.exe" BY Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where NOT match(process_path, "(?i)\\\\Program Files( \\(x86\\))?\\\\Synaptics\\\\") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "Synaptics.exe"
| where not(FolderPath has @"\Program Files\Synaptics\" or FolderPath has @"\Program Files (x86)\Synaptics\")
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, SHA256, MD5
| order by Timestamp desc
```

### Steam Workshop wallpaper '._cache_GAME1.exe' launcher execution

`UC_32_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.process_name="._cache_GAME1.exe" OR Processes.process_name LIKE "._cache_%.exe" BY Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName startswith "._cache_" and FileName endswith ".exe"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessParentFileName, SHA256, MD5
| order by Timestamp desc
```

### Wallpaper Engine spawning script interpreters or LOLBins

`UC_32_10` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.parent_process_name IN ("wallpaper32.exe","wallpaper64.exe","wallpaper_engine.exe") AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","mshta.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe") OR Processes.process_path LIKE "%\\AppData\\Local\\Temp\\%" OR Processes.process_path LIKE "%\\AppData\\Roaming\\%" OR Processes.process_path LIKE "%\\Users\\Public\\%") BY Processes.dest Processes.user Processes.process Processes.process_path Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("wallpaper32.exe","wallpaper64.exe","wallpaper_engine.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","mshta.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
   or FolderPath has_any (@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Users\Public\", @"\steamapps\workshop\content\431960\")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256, MD5
| order by Timestamp desc
```

### Trojanised AggregatorHost.dll loaded from non-system path

`UC_32_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem WHERE Filesystem.file_name="AggregatorHost.dll" AND NOT (Filesystem.file_path LIKE "%\\Windows\\System32\\%" OR Filesystem.file_path LIKE "%\\Windows\\SysWOW64\\%" OR Filesystem.file_path LIKE "%\\Windows\\WinSxS\\%") BY Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  (DeviceImageLoadEvents
   | where Timestamp > ago(14d)
   | where FileName =~ "AggregatorHost.dll"
   | where not(FolderPath has @"\Windows\System32\" or FolderPath has @"\Windows\SysWOW64\" or FolderPath has @"\Windows\WinSxS\")
   | project Timestamp, DeviceName, EventKind = "ImageLoad", FileName, FolderPath, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine),
  (DeviceFileEvents
   | where Timestamp > ago(14d)
   | where FileName =~ "AggregatorHost.dll"
   | where ActionType in ("FileCreated","FileModified","FileRenamed")
   | where not(FolderPath has @"\Windows\System32\" or FolderPath has @"\Windows\SysWOW64\" or FolderPath has @"\Windows\WinSxS\")
   | project Timestamp, DeviceName, EventKind = strcat("File:",ActionType), FileName, FolderPath, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessFolderPath = InitiatingProcessFolderPath, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### Steam credential file (loginusers.vdf / ssfn*) accessed by non-Steam process

`UC_32_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem WHERE (Filesystem.file_path LIKE "%\\Steam\\config\\%" OR Filesystem.file_name LIKE "ssfn%" OR Filesystem.file_name IN ("loginusers.vdf","config.vdf")) AND NOT Filesystem.process_name IN ("steam.exe","steamservice.exe","steamwebhelper.exe","steamerrorreporter.exe","steamerrorreporter64.exe") BY Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FolderPath has @"\Steam\config\" and (FileName in~ ("loginusers.vdf","config.vdf") or FileName startswith "ssfn"))
| where InitiatingProcessFileName !in~ ("steam.exe","steamservice.exe","steamwebhelper.exe","steamerrorreporter.exe","steamerrorreporter64.exe","steam_bootstrap.exe","explorer.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### C2 callback to malicious wallpaper campaign infrastructure

`UC_32_13` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Network_Traffic.All_Traffic WHERE (All_Traffic.dest IN ("120.48.156.17","202.144.192.29")) BY All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name All_Traffic.url | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  (DeviceNetworkEvents
   | where Timestamp > ago(30d)
   | where RemoteIP in ("120.48.156.17","202.144.192.29")
      or RemoteUrl has_any ("/ey.php","/audit.php","/download2/Themes2.zip")
   | project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessAccountName),
  (DeviceEvents
   | where Timestamp > ago(30d)
   | where ActionType in ("DnsQueryResponse","ConnectionSuccess")
   | where RemoteIP in ("120.48.156.17","202.144.192.29")
      or RemoteUrl has_any ("/ey.php","/audit.php","/download2/Themes2.zip")
   | project Timestamp, DeviceName, RemoteIP, RemotePort=tostring(RemotePort), RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256=InitiatingProcessSHA256, InitiatingProcessAccountName)
| order by Timestamp desc
```

### Known IOC hash match — malicious Steam Workshop wallpaper payloads

`UC_32_14` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.process_hash IN ("95856f2ce428c728d9781d3296558068","af080780cca2acd1d082ce01e7cc346a","c133c3dd9f7d6934598025047df41abf","d1693bbff456ae8fa3360446706df6da","8c2cc585ad8a13a72a704c0fda0c9854","b9fa763a53da3eea742d0f3c845a8c09","ded08ae5df7f1b12e5fdb767dbbed0b1","20965254e29104986e11939decd39549","18dedc0009f0927cba6425c84cce9883","0f4f01c6d495abb37403072dd017ce8d","5620f01284329f561b1839a36be55355","fe1f6485013cd5e6d5cf718049b0b8d6","74414ed4b63aadec039b603c32762b80") BY Processes.dest Processes.user Processes.process_name Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let IOCs = dynamic(["95856f2ce428c728d9781d3296558068","af080780cca2acd1d082ce01e7cc346a","c133c3dd9f7d6934598025047df41abf","d1693bbff456ae8fa3360446706df6da","8c2cc585ad8a13a72a704c0fda0c9854","b9fa763a53da3eea742d0f3c845a8c09","ded08ae5df7f1b12e5fdb767dbbed0b1","20965254e29104986e11939decd39549","18dedc0009f0927cba6425c84cce9883","0f4f01c6d495abb37403072dd017ce8d","5620f01284329f561b1839a36be55355","fe1f6485013cd5e6d5cf718049b0b8d6","74414ed4b63aadec039b603c32762b80"]);
union
  (DeviceProcessEvents | where Timestamp > ago(30d) | where MD5 in (IOCs) | project Timestamp, DeviceName, AccountName, Source="DeviceProcessEvents", FileName, FolderPath, MD5, SHA256, ProcessCommandLine, InitiatingProcessFileName),
  (DeviceFileEvents    | where Timestamp > ago(30d) | where MD5 in (IOCs) | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="DeviceFileEvents", FileName, FolderPath, MD5, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName),
  (DeviceImageLoadEvents | where Timestamp > ago(30d) | where MD5 in (IOCs) | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Source="DeviceImageLoadEvents", FileName, FolderPath, MD5, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName)
| order by Timestamp desc
```

### Persistence via Steam Workshop wallpaper content path in Run keys / Scheduled Tasks

`UC_32_15` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Registry WHERE (Registry.registry_path LIKE "%\\CurrentVersion\\Run%" OR Registry.registry_path LIKE "%\\CurrentVersion\\RunOnce%" OR Registry.registry_path LIKE "%\\Image File Execution Options\\%") AND (Registry.registry_value_data LIKE "%\\steamapps\\workshop\\content\\431960\\%" OR Registry.registry_value_data LIKE "%Synaptics.exe%" OR Registry.registry_value_data LIKE "%AggregatorHost.dll%" OR Registry.registry_value_data LIKE "%._cache_%.exe%") BY Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  (DeviceRegistryEvents
   | where Timestamp > ago(30d)
   | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
   | where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Image File Execution Options\", @"\Wow6432Node\Microsoft\Windows\CurrentVersion\Run")
   | where RegistryValueData has_any (@"\steamapps\workshop\content\431960\", "Synaptics.exe", "AggregatorHost.dll", "._cache_")
   | project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath),
  (DeviceEvents
   | where Timestamp > ago(30d)
   | where ActionType in ("ScheduledTaskCreated","ScheduledTaskUpdated")
   | where AdditionalFields has_any (@"\steamapps\workshop\content\431960\", "Synaptics.exe", "AggregatorHost.dll", "._cache_")
   | project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, AdditionalFields)
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

`UC_32_7` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
