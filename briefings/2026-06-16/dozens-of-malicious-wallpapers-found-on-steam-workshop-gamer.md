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
- **T1204.002** — Malicious File
- **T1059.001** — PowerShell
- **T1059.003** — Windows Command Shell
- **T1574.002** — DLL Side-Loading
- **T1036.005** — Match Legitimate Name or Location
- **T1059** — Command and Scripting Interpreter
- **T1528** — Steal Application Access Token
- **T1041** — Exfiltration Over C2 Channel
- **T1105** — Ingress Tool Transfer
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1588.001** — Malware

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Wallpaper Engine spawning LOLBins or staged binaries (Steam Workshop wallpaper malware)

`UC_168_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wallpaper32.exe","wallpaper64.exe") AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","Synaptics.exe") OR Processes.process IN ("*\\._cache_*.exe","*\\AppData\\Local\\Temp\\*","*\\AppData\\Roaming\\*","*\\ProgramData\\*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("wallpaper32.exe","wallpaper64.exe")
| where AccountName !endswith "$"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","Synaptics.exe")
    or FileName startswith "._cache_"
    or FolderPath has_any (@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\ProgramData\")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Campaign loader '._cache_GAME1.exe' execution (Steam wallpaper malware)

`UC_168_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="._cache_GAME1.exe" OR Processes.process="*\\._cache_*.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName startswith "._cache_"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, SHA256, MD5
| order by Timestamp desc
```

### DarkKomet Synaptics.exe backdoor executing from ProgramData

`UC_168_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="Synaptics.exe" AND Processes.process_path="*\\ProgramData\\Synaptics\\*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "Synaptics.exe"
| where FolderPath has @"\ProgramData\Synaptics\"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, SHA256, MD5
| order by Timestamp desc
```

### Tampered AggregatorHost.dll loaded/dropped (Steam session credential theft)

`UC_168_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="AggregatorHost.dll" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | search NOT file_path IN ("*\\Windows\\System32\\*","*\\Windows\\SysWOW64\\*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "AggregatorHost.dll"
| where not(FolderPath has @"\Windows\System32\" or FolderPath has @"\Windows\SysWOW64\")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### C2 communication to Steam wallpaper campaign infrastructure (120.48.156.17 / 202.144.192.29)

`UC_168_12` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("120.48.156.17","202.144.192.29") by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("120.48.156.17","202.144.192.29")
    or RemoteUrl has_any ("120.48.156.17/ey.php","202.144.192.29/audit.php","download2/Themes2.zip")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### DarkKomet 'Synaptics Pointing Device Driver' Run-key persistence to ProgramData

`UC_168_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentVersion\\Run*" AND Registry.registry_value_data="*\\ProgramData\\Synaptics\\Synaptics.exe*" by Registry.dest Registry.registry_key_name Registry.registry_value_name Registry.registry_value_data Registry.process_guid | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueData has @"\ProgramData\Synaptics\Synaptics.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### Steam wallpaper campaign payload hash sweep (DarkKomet / Lumma / Vidar / RenEngine)

`UC_168_14` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("95856f2ce428c728d9781d3296558068","af080780cca2acd1d082ce01e7cc346a","c133c3dd9f7d6934598025047df41abf","d1693bbff456ae8fa3360446706df6da","8c2cc585ad8a13a72a704c0fda0c9854","b9fa763a53da3eea742d0f3c845a8c09","ded08ae5df7f1b12e5fdb767dbbed0b1","20965254e29104986e11939decd39549","18dedc0009f0927cba6425c84cce9883","0f4f01c6d495abb37403072dd017ce8d","5620f01284329f561b1839a36be55355","fe1f6485013cd5e6d5cf718049b0b8d6","74414ed4b63aadec039b603c32762b80") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CampaignMD5 = dynamic(["95856f2ce428c728d9781d3296558068","af080780cca2acd1d082ce01e7cc346a","c133c3dd9f7d6934598025047df41abf","d1693bbff456ae8fa3360446706df6da","8c2cc585ad8a13a72a704c0fda0c9854","b9fa763a53da3eea742d0f3c845a8c09","ded08ae5df7f1b12e5fdb767dbbed0b1","20965254e29104986e11939decd39549","18dedc0009f0927cba6425c84cce9883","0f4f01c6d495abb37403072dd017ce8d","5620f01284329f561b1839a36be55355","fe1f6485013cd5e6d5cf718049b0b8d6","74414ed4b63aadec039b603c32762b80"]);
union
( DeviceProcessEvents | where Timestamp > ago(30d) | where MD5 in~ (CampaignMD5) | extend Surface="Process", Actor=AccountName ),
( DeviceFileEvents | where Timestamp > ago(30d) | where MD5 in~ (CampaignMD5) | extend Surface="File", Actor=InitiatingProcessAccountName )
| project Timestamp, DeviceName, Surface, Actor, FileName, FolderPath, MD5, SHA256, InitiatingProcessFileName
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

`UC_168_7` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
