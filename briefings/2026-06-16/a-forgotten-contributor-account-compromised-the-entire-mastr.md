# [CRIT] A Forgotten Contributor Account Compromised the Entire Mastra npm Package Scope

**Source:** Snyk
**Published:** 2026-06-16
**Article:** https://snyk.io/blog/a-forgotten-contributor-account-compromised-the-entire-mastra-npm-package-scope/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
Marian Corneci 
June 16, 2026
0 mins read An attacker republished the entire @mastra npm scope on June 17, 2026, slipping a single malicious dependency into 143 packages and counting, including @mastra/core , which pulls roughly 4 million downloads a month and has hundreds of dependent projects. The injected dependency, easy-day-js , is a dayjs lookalike whose install hook disables TLS verification, downloads a second-stage payload from a raw IP ad…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.254.164.92`
- **IPv4 (defanged):** `23.254.164.123`
- **Domain (defanged):** `hwsrv-1327786.hostwindsdns.com`
- **Domain (defanged):** `hwsrv-1327785.hostwindsdns.com`
- **SHA256:** `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`
- **SHA256:** `b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4`
- **SHA256:** `c38954e85bf5433e61e7c8f4230336695624ae88b6953afabf7bf817aa91b638`
- **SHA256:** `cdec8b20338beb708b5be8d3d7a3041a35a8b0fb92f9186262f312d55ff82066`
- **SHA256:** `9570f77a5e1511869f4e554e7166df9fde081f2583e293c2569621792ed7d9c9`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1543.001** — Persistence (article-specific)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1571** — Non-Standard Port
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1070.004** — Indicator Removal: File Deletion
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Mastra npm supply chain — outbound connection to attacker IPs 23.254.164.92 / .123

`UC_105_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_ip IN ("23.254.164.92","23.254.164.123") by All_Traffic.src All_Traffic.user All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.process_name
| `drop_dm_object_name(All_Traffic)`
| eval risk_note=case(dest_ip=="23.254.164.92","easy-day-js dropper (port 8000)",dest_ip=="23.254.164.123","RAT C2 (~10m beacon)")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in ("23.254.164.92", "23.254.164.123")
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName, InitiatingProcessAccountName
| extend Note = case(RemoteIP == "23.254.164.92", "easy-day-js postinstall dropper :8000", RemoteIP == "23.254.164.123", "second-stage RAT C2 (~10m beacon)", "unknown")
| order by Timestamp desc
```

### easy-day-js postinstall marker files (.pkg_history / .pkg_logs) created in user profile

`UC_105_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name=".pkg_history" OR Filesystem.file_name=".pkg_logs") AND Filesystem.action IN ("created","modified") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName in~ (".pkg_history",".pkg_logs")
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","node","npm","yarn","pnpm.exe","pnpm")
   or InitiatingProcessParentFileName in~ ("node.exe","npm.exe","npm-cli.js","yarn","pnpm.exe")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Windows persistence drop under C:\ProgramData\NodePackages by node/PowerShell

`UC_105_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="C:\\ProgramData\\NodePackages\\*" by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath startswith @"C:\ProgramData\NodePackages"
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Node.js process reading Chromium browser wallet/profile data (Mastra stealer)

`UC_105_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node") AND (Filesystem.file_path="*\\Local Extension Settings\\*" OR Filesystem.file_path="*\\Login Data*" OR Filesystem.file_path="*\\Cookies*" OR Filesystem.file_path="*\\Web Data*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where FolderPath has_any (
    @"\Google\Chrome\User Data",
    @"\BraveSoftware\Brave-Browser\User Data",
    @"\Microsoft\Edge\User Data"
  )
| where FileName in~ ("Login Data","Cookies","Web Data","Login Data For Account") or FolderPath has @"\Local Extension Settings\"
| where InitiatingProcessParentFileName !in~ ("electron.exe","code.exe","slack.exe","discord.exe","teams.exe")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
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

### Article-specific behavioural hunt — A Forgotten Contributor Account Compromised the Entire Mastra npm Package Scope

`UC_105_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — A Forgotten Contributor Account Compromised the Entire Mastra npm Package Scope ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("dayjs.min.js") OR Processes.process_path="*C:\ProgramData\NodePackages*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\ProgramData\NodePackages*" OR Filesystem.file_path="*/Library/LaunchAgents/com.nvm.protocal.plist*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("dayjs.min.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — A Forgotten Contributor Account Compromised the Entire Mastra npm Package Scope
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("dayjs.min.js") or FolderPath has_any ("C:\ProgramData\NodePackages"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\ProgramData\NodePackages", "/Library/LaunchAgents/com.nvm.protocal.plist", "/dev/null") or FileName in~ ("dayjs.min.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `23.254.164.92`, `23.254.164.123`, `hwsrv-1327786.hostwindsdns.com`, `hwsrv-1327785.hostwindsdns.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`, `b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4`, `c38954e85bf5433e61e7c8f4230336695624ae88b6953afabf7bf817aa91b638`, `cdec8b20338beb708b5be8d3d7a3041a35a8b0fb92f9186262f312d55ff82066`, `9570f77a5e1511869f4e554e7166df9fde081f2583e293c2569621792ed7d9c9`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
