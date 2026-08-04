# [CRIT] Fake Roblox Xeno script launcher pushes infostealer, RAT malware

**Source:** BleepingComputer
**Published:** 2026-08-03
**Article:** https://www.bleepingcomputer.com/news/security/fake-roblox-xeno-script-launcher-pushes-infostealer-rat-malware/

## Threat Profile

Fake Roblox Xeno script launcher pushes infostealer, RAT malware 
By Bill Toulas 
August 3, 2026
03:25 PM
0 
Fake Xeno Executor installers are infecting unsuspecting Roblox players with malware that provides remote access and steals sensitive information.
Xeno Executor is a popular Roblox utility for running scripts that players can use to automate actions or run custom code on the platform, including cheats.
The tool isn’t an official part of the game, so the Roblox client periodically blocks e…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1140** — Deobfuscate/Decode Files or Information
- **T1082** — System Information Discovery
- **T1119** — Automated Collection
- **T1554** — Compromise Host Software Binary
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Fake Xeno loader (xeno.exe) executed from archive/Downloads/Temp staging

`UC_4_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="xeno.exe" AND (Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.parent_process_name IN ("winrar.exe","7zfm.exe","7zg.exe","7z.exe","explorer.exe","winzip32.exe")) by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "xeno.exe"
| where FolderPath has_any (@"\Downloads\", @"\AppData\Local\Temp\", @"\Temp\")
   or InitiatingProcessFileName in~ ("winrar.exe","7zfm.exe","7zg.exe","7z.exe","explorer.exe","winzip32.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Java runtime (javaw.exe/jvm.dll) dropped to AppData by non-installer process

`UC_4_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("javaw.exe","java.exe","jvm.dll") AND (Filesystem.file_path="*\\AppData\\Local\\Java\\*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*\\AppData\\Local\\Xeno\\*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("msiexec.exe","jdk-*installer*.exe","javasetup.exe","setup.exe") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("javaw.exe","java.exe","jvm.dll")
| where FolderPath has_any (@"\AppData\Local\Java\", @"\AppData\Local\Temp\", @"\AppData\Local\Xeno\")
| where InitiatingProcessFileName !in~ ("msiexec.exe","setup.exe","javasetup.exe","jdk-installer.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Obfuscated decompiler.exe spawned by xeno.exe / javaw (second-stage masquerade)

`UC_4_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="decompiler.exe" AND (Processes.parent_process_name IN ("xeno.exe","javaw.exe","java.exe") OR Processes.process_path="*\\AppData\\Local\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.parent_process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "decompiler.exe"
| where InitiatingProcessFileName in~ ("xeno.exe","javaw.exe","java.exe") or FolderPath has @"\AppData\Local\"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Single process reading credential stores across 3+ browsers (stealer sweep)

`UC_4_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("Login Data","Cookies","Web Data","Local State") by Filesystem.dest Filesystem.process_id Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | eval browser=case(match(file_path,"(?i)\\\\Google\\\\Chrome\\\\"),"Chrome",match(file_path,"(?i)\\\\Microsoft\\\\Edge\\\\"),"Edge",match(file_path,"(?i)BraveSoftware"),"Brave",match(file_path,"(?i)Opera Software"),"Opera",match(file_path,"(?i)\\\\Vivaldi\\\\"),"Vivaldi") | where isnotnull(browser) | search NOT process_name IN ("chrome.exe","msedge.exe","brave.exe","opera.exe","vivaldi.exe","msedgewebview2.exe") | stats dc(browser) as browser_count values(browser) as browsers values(file_path) as paths by dest process_name process_id | where browser_count>=3
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("Login Data","Cookies","Web Data","Local State")
| extend Browser = case(
    FolderPath has @"\Google\Chrome\", "Chrome",
    FolderPath has @"\Microsoft\Edge\", "Edge",
    FolderPath has @"\BraveSoftware\", "Brave",
    FolderPath has @"\Opera Software\", "Opera",
    FolderPath has @"\Vivaldi\", "Vivaldi",
    "Other")
| where Browser != "Other"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","brave.exe","opera.exe","vivaldi.exe","msedgewebview2.exe","explorer.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize BrowserFamilies = make_set(Browser), BrowserCount = dcount(Browser), FilesTouched = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessAccountName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath
| where BrowserCount >= 3   // 3+ distinct browser credential stores by one non-browser process = stealer sweep
| order by LastSeen desc
```

### Exodus wallet app.asar tamper / SquirrelInteractive.bin drop by non-Exodus process

`UC_4_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where ((Filesystem.file_name="app.asar" AND Filesystem.file_path="*\\exodus\\*") OR Filesystem.file_name="SquirrelInteractive.bin") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | search NOT process_name IN ("Exodus.exe","Update.exe","msiexec.exe") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName =~ "app.asar" and FolderPath has @"\exodus\") or FileName =~ "SquirrelInteractive.bin"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName !in~ ("Exodus.exe","Update.exe","msiexec.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### 'Display Calibration' Run key persistence pointing to AppData javaw/GameDVR

`UC_4_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentVersion\\Run*" AND (Registry.registry_value_name="Display Calibration" OR Registry.registry_value_data="*\\AppData\\Local\\Java\\jre\\bin\\javaw.exe*" OR Registry.registry_value_data="*\\Microsoft\\GameDVR\\*") by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueName =~ "Display Calibration"
   or RegistryValueData has_any (@"\AppData\Local\Java\jre\bin\javaw.exe", @"\Microsoft\GameDVR\", "decompiler")
| where InitiatingProcessFileName !in~ ("dccw.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Xeno RAT C2 egress to solthere.net / dynamic .xyz WebSocket from AppData Java

`UC_4_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="*solthere.net*" OR (All_Traffic.app IN ("javaw.exe","java.exe","decompiler.exe") AND All_Traffic.dest="*.xyz")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "solthere.net"
    or (InitiatingProcessFileName in~ ("javaw.exe","java.exe","decompiler.exe") and InitiatingProcessFolderPath has @"\AppData\Local\" and RemoteUrl endswith ".xyz")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
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

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### Article-specific behavioural hunt — Fake Roblox Xeno script launcher pushes infostealer, RAT malware

`UC_4_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Fake Roblox Xeno script launcher pushes infostealer, RAT malware ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("xeno.exe","decompiler.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("xeno.exe","decompiler.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Fake Roblox Xeno script launcher pushes infostealer, RAT malware
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("xeno.exe", "decompiler.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("xeno.exe", "decompiler.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 12 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
