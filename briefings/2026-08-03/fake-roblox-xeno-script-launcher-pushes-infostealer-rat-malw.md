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
- **T1105** — Ingress Tool Transfer
- **T1518** — Software Discovery
- **T1083** — File and Directory Discovery
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Fake Xeno loader (xeno.exe) executed from archive/Downloads or Xeno cache path

`UC_4_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="xeno.exe" (Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\AppData\\Roaming\\*" OR Processes.process_path="*\\AppData\\Local\\Xeno\\workspace\\cache\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "xeno.exe"
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\Downloads\", @"\AppData\Roaming\", @"\AppData\Local\Xeno\workspace\cache\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessCommandLine, ParentProcess = InitiatingProcessFileName,
          ParentPath = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine
| order by Timestamp desc
```

### Java runtime (javaw.exe) extracted to %LOCALAPPDATA%\Java by fake Xeno loader

`UC_4_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="javaw.exe" OR Filesystem.file_name="java.exe") Filesystem.file_path="*\\AppData\\Local\\Java\\*" by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ ("javaw.exe", "java.exe")
| where FolderPath has @"\AppData\Local\Java\"
| where InitiatingProcessFileName !in~ ("msiexec.exe", "setup.exe", "jre-installer.exe", "java_installer.exe", "jdk-installer.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath,
          Dropper = InitiatingProcessFileName, DropperPath = InitiatingProcessFolderPath,
          DropperCmd = InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### decompiler.exe (masqueraded Java JAR) spawned by javaw.exe / xeno.exe

`UC_4_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="decompiler.exe" (Processes.parent_process_name="javaw.exe" OR Processes.parent_process_name="java.exe" OR Processes.parent_process_name="xeno.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "decompiler.exe"
| where InitiatingProcessFileName in~ ("javaw.exe", "java.exe", "xeno.exe")
     or FolderPath has @"\AppData\Local\"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine,
          Parent = InitiatingProcessFileName, ParentPath = InitiatingProcessFolderPath, ParentCmd = InitiatingProcessCommandLine
| order by Timestamp desc
```

### Single non-browser process reads credential stores across 3+ browsers (Chrome/Edge/Brave/Opera/Vivaldi)

`UC_4_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_name="Login Data" OR Filesystem.file_name="Cookies" OR Filesystem.file_name="Web Data" OR Filesystem.file_name="Local State") (Filesystem.file_path="*\\Google\\Chrome\\*" OR Filesystem.file_path="*\\Microsoft\\Edge\\*" OR Filesystem.file_path="*\\BraveSoftware\\*" OR Filesystem.file_path="*\\Opera Software\\*" OR Filesystem.file_path="*\\Vivaldi\\*") Filesystem.process_name!="chrome.exe" Filesystem.process_name!="msedge.exe" Filesystem.process_name!="brave.exe" Filesystem.process_name!="opera.exe" Filesystem.process_name!="vivaldi.exe" by Filesystem.dest Filesystem.process_name Filesystem.process_id | eval browsers=mvdedup(mvmap(paths, case(like(paths,"%Google\Chrome%"),"Chrome", like(paths,"%Microsoft\Edge%"),"Edge", like(paths,"%BraveSoftware%"),"Brave", like(paths,"%Opera Software%"),"Opera", like(paths,"%Vivaldi%"),"Vivaldi"))) | eval browser_count=mvcount(browsers) | where browser_count>=3 | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName in~ ("Login Data", "Cookies", "Web Data", "Local State")
| where FolderPath has_any (@"\Google\Chrome\", @"\Microsoft\Edge\", "BraveSoftware", "Opera Software", @"\Vivaldi\")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","brave.exe","opera.exe","opera_gx.exe","vivaldi.exe","explorer.exe","onedrive.exe")
| extend Browser = case(
    FolderPath has @"\Google\Chrome\", "Chrome",
    FolderPath has @"\Microsoft\Edge\", "Edge",
    FolderPath has "BraveSoftware", "Brave",
    FolderPath has "Opera Software", "Opera",
    FolderPath has @"\Vivaldi\", "Vivaldi", "Other")
| summarize BrowserCount = dcount(Browser), Browsers = make_set(Browser),
            StoreSamples = make_set(FolderPath, 10), StartTime = min(Timestamp), EndTime = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessFolderPath, InitiatingProcessAccountName
| where BrowserCount >= 3   // one non-browser process touching >=3 of the 5 targeted browsers
| order by BrowserCount desc
```

### Exodus wallet tamper (app.asar) / multi-wallet enumeration by non-wallet process

`UC_4_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_path) as paths values(Filesystem.action) as actions from datamodel=Endpoint.Filesystem where ((Filesystem.file_name="app.asar" AND Filesystem.file_path="*\\Exodus\\*") OR Filesystem.file_path="*\\Exodus\\exodus.wallet\\*" OR Filesystem.file_path="*\\Electrum\\wallets\\*" OR Filesystem.file_path="*\\Ledger Live\\*" OR Filesystem.file_path="*\\atomic\\Local Storage\\*") Filesystem.process_name!="Exodus.exe" Filesystem.process_name!="Electrum.exe" Filesystem.process_name!="atomic.exe" by Filesystem.dest Filesystem.process_name Filesystem.process_id | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FileName =~ "app.asar" and FolderPath has @"\Exodus\")
     or FolderPath has_any (@"\Exodus\exodus.wallet\", @"\Electrum\wallets\", @"\Ledger Live\", @"\atomic\Local Storage\", @"\Coinomi\")
| where InitiatingProcessFileName !in~ ("exodus.exe", "electrum.exe", "ledger live.exe", "atomic.exe", "update.exe", "electron.exe")
| summarize WalletHits = count(), Ops = make_set(ActionType), Paths = make_set(FolderPath, 15),
            AsarWrite = countif(FileName =~ "app.asar" and ActionType in ("FileModified","FileCreated")),
            StartTime = min(Timestamp), EndTime = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessFolderPath, InitiatingProcessAccountName
| where AsarWrite > 0 or WalletHits >= 2
| order by AsarWrite desc, WalletHits desc
```

### 'Display Calibration' Run key persistence pointing to LocalAppData Java/GameDVR payload

`UC_4_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\CurrentVersion\\Run*" (Registry.registry_value_name="Display Calibration" OR Registry.registry_value_data="*\\AppData\\Local\\Java\\*" OR Registry.registry_value_data="*\\AppData\\Local\\Microsoft\\GameDVR*" OR Registry.registry_value_data="*javaw.exe*") by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueName =~ "Display Calibration"
     or RegistryValueData has_any (@"\AppData\Local\Java\", @"\AppData\Local\Microsoft\GameDVR", "javaw.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData,
          Writer = InitiatingProcessFileName, WriterPath = InitiatingProcessFolderPath, WriterCmd = InitiatingProcessCommandLine
| order by Timestamp desc
```

### Fake Xeno C2 beacon to solthere.net / LocalAppData javaw.exe public egress

`UC_4_11` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="*solthere.net*" OR (All_Traffic.app="javaw.exe" AND All_Traffic.dest_is_internal="false" AND (All_Traffic.process_path="*\\AppData\\Local\\Java\\*" OR All_Traffic.process_path="*\\AppData\\Local\\Microsoft\\GameDVR*"))) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_path | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "solthere.net"
     or (InitiatingProcessFileName =~ "javaw.exe"
         and InitiatingProcessFolderPath has_any (@"\AppData\Local\Java\", @"\AppData\Local\Microsoft\GameDVR")
         and RemoteIPType == "Public")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
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

Severity classified as **CRIT** based on: 12 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
