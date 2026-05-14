# [HIGH] GlassWorm goes native: New Zig dropper infects every IDE on your machine

**Source:** Aikido
**Published:** 2026-04-08
**Article:** https://www.aikido.dev/blog/glassworm-zig-dropper-infects-every-ide-on-your-machine

## Threat Profile

Blog Vulnerabilities & Threats GlassWorm goes native: New Zig dropper infects every IDE on your machine GlassWorm goes native: New Zig dropper infects every IDE on your machine Written by Ilyas Makari Published on: Apr 8, 2026 We have been tracking GlassWorm for over a year. It first appeared in March 2025 , when Aikido discovered malicious npm packages hiding payloads inside invisible Unicode characters. The campaign has expanded repeatedly since then, compromising hundreds of projects across G…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `2819ea44e22b9c47049e86894e544f3fd0de1d8afc7b545314bd3bc718bf2e02`
- **SHA256:** `112d1b33dd9b0244525f51e59e6a79ac5ae452bf6e98c310e7b4fa7902e4db44`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1129** — Shared Modules
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1546** — Event Triggered Execution
- **T1105** — Ingress Tool Transfer
- **T1102.001** — Web Service: Dead Drop Resolver

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GlassWorm Zig dropper native node addon (win.node/mac.node) written to IDE extension bin/ folder

`UC_290_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("2819ea44e22b9c47049e86894e544f3fd0de1d8afc7b545314bd3bc718bf2e02","112d1b33dd9b0244525f51e59e6a79ac5ae452bf6e98c310e7b4fa7902e4db44")) OR (Filesystem.file_name IN ("win.node","mac.node") AND (Filesystem.file_path="*\\.vscode\\extensions\\*\\bin\\*" OR Filesystem.file_path="*\\.cursor\\extensions\\*\\bin\\*" OR Filesystem.file_path="*\\.windsurf\\extensions\\*\\bin\\*" OR Filesystem.file_path="*\\.vscode-oss\\extensions\\*\\bin\\*" OR Filesystem.file_path="*\\Positron\\*extensions*\\bin\\*" OR Filesystem.file_path="*/.vscode/extensions/*/bin/*" OR Filesystem.file_path="*/.cursor/extensions/*/bin/*")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (SHA256 in~ ("2819ea44e22b9c47049e86894e544f3fd0de1d8afc7b545314bd3bc718bf2e02",
                    "112d1b33dd9b0244525f51e59e6a79ac5ae452bf6e98c310e7b4fa7902e4db44"))
      or (FileName in~ ("win.node","mac.node")
          and (FolderPath has @"\.vscode\extensions\"
               or FolderPath has @"\.vscode-oss\extensions\"
               or FolderPath has @"\.cursor\extensions\"
               or FolderPath has @"\.windsurf\extensions\"
               or FolderPath has @"\Positron\"
               or FolderPath has "/.vscode/extensions/"
               or FolderPath has "/.cursor/extensions/"
               or FolderPath has "/.windsurf/extensions/")
          and FolderPath has @"\bin")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] Force-install of IDE extension via cmd.exe with --install-extension flag spawned by node host

`UC_290_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="cmd.exe" Processes.process="*--install-extension*" (Processes.process="*code.cmd*" OR Processes.process="*code-insiders.cmd*" OR Processes.process="*cursor.cmd*" OR Processes.process="*windsurf.cmd*" OR Processes.process="*codium.cmd*" OR Processes.process="*positron.cmd*") Processes.process="*/d*" Processes.process="*/e:ON*" Processes.process="*/v:OFF*" Processes.parent_process_name!="explorer.exe" by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has "--install-extension"
| where ProcessCommandLine has "/d" and ProcessCommandLine has "/e:ON" and ProcessCommandLine has "/v:OFF"
| where ProcessCommandLine has_any ("code.cmd","code-insiders.cmd","cursor.cmd","windsurf.cmd","codium.cmd","positron.cmd")
| where AccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("explorer.exe","msiexec.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentFile  = InitiatingProcessFileName,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildCmd    = ProcessCommandLine
| order by Timestamp desc
```

### [LLM] Outbound fetch of attacker-controlled autoimport VSIX from ColossusQuailPray GitHub release

`UC_290_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*ColossusQuailPray/oiegjqde*" OR Web.url="*autoimport-2.7.9.vsix*") by Web.src Web.dest Web.user Web.url Web.http_user_agent Web.app | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
  ( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any ("ColossusQuailPray/oiegjqde", "autoimport-2.7.9.vsix")
    | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, ActionType ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "autoimport-2.7.9.vsix" or FileOriginUrl has_any ("ColossusQuailPray/oiegjqde", "autoimport-2.7.9.vsix")
    | project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, RemoteUrl = FileOriginUrl, ActionType )
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

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Article-specific behavioural hunt — GlassWorm goes native: New Zig dropper infects every IDE on your machine

`UC_290_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — GlassWorm goes native: New Zig dropper infects every IDE on your machine ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","code.cmd","code-insiders.cmd","cursor.cmd","windsurf.cmd","codium.cmd","positron.cmd") OR Processes.process_path="*%LOCALAPPDATA%\Programs\Microsoft*" OR Processes.process_path="*%LOCALAPPDATA%\Programs\cursor\resources\app\bin\cursor.cmd*" OR Processes.process_path="*%LOCALAPPDATA%\Programs\windsurf\resources\app\bin\windsurf.cmd*" OR Processes.process_path="*%LOCALAPPDATA%\Programs\VSCodium\resources\app\bin\codium.cmd*" OR Processes.process_path="*%LOCALAPPDATA%\Programs\Positron\resources\app\bin\positron.cmd*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%LOCALAPPDATA%\Programs\Microsoft*" OR Filesystem.file_path="*%LOCALAPPDATA%\Programs\cursor\resources\app\bin\cursor.cmd*" OR Filesystem.file_path="*%LOCALAPPDATA%\Programs\windsurf\resources\app\bin\windsurf.cmd*" OR Filesystem.file_path="*%LOCALAPPDATA%\Programs\VSCodium\resources\app\bin\codium.cmd*" OR Filesystem.file_path="*%LOCALAPPDATA%\Programs\Positron\resources\app\bin\positron.cmd*" OR Filesystem.file_path="*%ProgramFiles%\Positron\resources\app\bin\positron.cmd*" OR Filesystem.file_name IN ("node.js","code.cmd","code-insiders.cmd","cursor.cmd","windsurf.cmd","codium.cmd","positron.cmd"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — GlassWorm goes native: New Zig dropper infects every IDE on your machine
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "code.cmd", "code-insiders.cmd", "cursor.cmd", "windsurf.cmd", "codium.cmd", "positron.cmd") or FolderPath has_any ("%LOCALAPPDATA%\Programs\Microsoft", "%LOCALAPPDATA%\Programs\cursor\resources\app\bin\cursor.cmd", "%LOCALAPPDATA%\Programs\windsurf\resources\app\bin\windsurf.cmd", "%LOCALAPPDATA%\Programs\VSCodium\resources\app\bin\codium.cmd", "%LOCALAPPDATA%\Programs\Positron\resources\app\bin\positron.cmd"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%LOCALAPPDATA%\Programs\Microsoft", "%LOCALAPPDATA%\Programs\cursor\resources\app\bin\cursor.cmd", "%LOCALAPPDATA%\Programs\windsurf\resources\app\bin\windsurf.cmd", "%LOCALAPPDATA%\Programs\VSCodium\resources\app\bin\codium.cmd", "%LOCALAPPDATA%\Programs\Positron\resources\app\bin\positron.cmd", "%ProgramFiles%\Positron\resources\app\bin\positron.cmd") or FileName in~ ("node.js", "code.cmd", "code-insiders.cmd", "cursor.cmd", "windsurf.cmd", "codium.cmd", "positron.cmd"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2819ea44e22b9c47049e86894e544f3fd0de1d8afc7b545314bd3bc718bf2e02`, `112d1b33dd9b0244525f51e59e6a79ac5ae452bf6e98c310e7b4fa7902e4db44`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
