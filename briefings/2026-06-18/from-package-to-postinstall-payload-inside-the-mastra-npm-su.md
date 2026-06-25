# [HIGH] From package to postinstall payload: Inside the Mastra npm supply chain compromise by Sapphire Sleet

**Source:** Microsoft Security Blog
**Published:** 2026-06-18
**Article:** https://www.microsoft.com/en-us/security/blog/2026/06/17/postinstall-payload-inside-mastra-npm-supply-chain-compromise/

## Threat Profile

Tags 
Malware 
npm 
Content types 
Research 
Products and services 
Microsoft Defender 
Topics 
Actionable threat insights 
Microsoft Threat Intelligence observed a large-scale npm supply chain attack affecting 140+ packages across the mastra and @mastra scopes on the npm registry. Microsoft shared its findings with the npm security team, and the compromised packages have been removed and the attacker’s publish access to the @mastra scope has been revoked. The compromise originated from the take…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.254.164.92`
- **IPv4 (defanged):** `23.254.164.123`
- **Domain (defanged):** `hwsrv-1327786.hostwindsdns.com`
- **Domain (defanged):** `hwsrv-1327785.hostwindsdns.com`
- **SHA256:** `b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4`
- **SHA256:** `c38954e85bf5433e61e7c8f4230336695624ae88b6953afabf7bf817aa91b638`
- **SHA256:** `cdec8b20338beb708b5be8d3d7a3041a35a8b0fb92f9186262f312d55ff82066`
- **SHA256:** `9570f77a5e1511869f4e554e7166df9fde081f2583e293c2569621792ed7d9c9`
- **SHA256:** `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1543.001** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1564.003** — Hide Artifacts: Hidden Window

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Sapphire Sleet npm postinstall dropper: node executing easy-day-js setup.cjs

`UC_124_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("node.exe","node") AND (Processes.process="*setup.cjs*" OR Processes.process="*easy-day-js*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node")
| where ProcessCommandLine has_any ("setup.cjs", "easy-day-js")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp desc
```

### Mastra easy-day-js C2 beacon to 23.254.164.92 / 23.254.164.123

`UC_124_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("23.254.164.92","23.254.164.123")) by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("23.254.164.92", "23.254.164.123")
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp desc
```

### easy-day-js persistence: NvmProtocal Run key / ProgramData NodePackages autostart

`UC_124_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_value_name="NvmProtocal" OR Registry.registry_value_data="*NodePackages*") by Registry.dest Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid
| `drop_dm_object_name(Registry)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryValueName =~ "NvmProtocal" or RegistryValueData has "NodePackages"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| sort by Timestamp desc
```

### easy-day-js install markers: .pkg_history / .pkg_logs dropped by Node.js

`UC_124_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN (".pkg_history",".pkg_logs")) by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_guid
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName in~ (".pkg_history", ".pkg_logs")
| where InitiatingProcessFileName in~ ("node.exe", "node")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| sort by Timestamp desc
```

### easy-day-js second stage: detached Node.js executing .js from ProgramData NodePackages

`UC_124_13` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("node.exe","node") AND Processes.parent_process_name IN ("node.exe","node") AND Processes.process="*NodePackages*" AND Processes.process="*.js*") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("node.exe", "node")
| where InitiatingProcessFileName in~ ("node.exe", "node")
| where ProcessCommandLine has "NodePackages" and ProcessCommandLine has ".js"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| sort by Timestamp desc
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

### Article-specific behavioural hunt — From package to postinstall payload: Inside the Mastra npm supply chain compromi

`UC_124_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — From package to postinstall payload: Inside the Mastra npm supply chain compromi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","dayjs.min.js") OR Processes.process_path="*C:\ProgramData\NodePackages\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\ProgramData\NodePackages\*" OR Filesystem.file_path="*/Library/NodePackages/*" OR Filesystem.file_name IN ("node.js","dayjs.min.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — From package to postinstall payload: Inside the Mastra npm supply chain compromi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "dayjs.min.js") or FolderPath has_any ("C:\ProgramData\NodePackages\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\ProgramData\NodePackages\", "/Library/NodePackages/") or FileName in~ ("node.js", "dayjs.min.js"))
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
  - file hash IOC(s): `b122a9873bedf145ae2a7fd024b5f309007dbb025149f4dc4ac3f7e4f32a36a4`, `c38954e85bf5433e61e7c8f4230336695624ae88b6953afabf7bf817aa91b638`, `cdec8b20338beb708b5be8d3d7a3041a35a8b0fb92f9186262f312d55ff82066`, `9570f77a5e1511869f4e554e7166df9fde081f2583e293c2569621792ed7d9c9`, `221c45a790dec2a296af57969e1165a16f8f49733aeab64c0bbd768d9943badf`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 14 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
