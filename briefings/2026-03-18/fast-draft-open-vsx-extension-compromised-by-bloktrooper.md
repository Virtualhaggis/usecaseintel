# [CRIT] fast-draft Open VSX Extension Compromised by BlokTrooper

**Source:** Aikido
**Published:** 2026-03-18
**Article:** https://www.aikido.dev/blog/fast-draft-open-vsx-bloktrooper

## Threat Profile

Blog Vulnerabilities & Threats fast-draft Open VSX Extension Compromised by BlokTrooper fast-draft Open VSX Extension Compromised by BlokTrooper Written by Raphael Silva Published on: Mar 18, 2026 The KhangNghiem/fast-draft extension, listed on open-vsx.org/extension/KhangNghiem/fast-draft and now sitting above 26,000 downloads, had multiple malicious releases that execute a GitHub-hosted downloader and pull a second-stage RAT and infostealer from the BlokTrooper/extension repository. The confir…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `195.201.104.53`
- **Domain (defanged):** `raw.githubusercontent.com/BlokTrooper/extension`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.003** — Windows Command Shell
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1095** — Non-Application Layer Protocol
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1059.007** — JavaScript
- **T1106** — Native API
- **T1564.003** — Hidden Window

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### VSCode/VSCodium spawning shell or curl to raw.githubusercontent.com/BlokTrooper

`UC_545_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("Code.exe","Code - Insiders.exe","VSCodium.exe","Cursor.exe","node.exe") AND Processes.process_name IN ("curl.exe","cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe") AND Processes.process="*raw.githubusercontent.com*" AND Processes.process="*BlokTrooper*" by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("Code.exe","Code - Insiders.exe","VSCodium.exe","Cursor.exe","node.exe")
| where FileName in~ ("curl.exe","cmd.exe","sh.exe","bash.exe","wsl.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has "raw.githubusercontent.com" and ProcessCommandLine has "BlokTrooper"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Outbound TCP beacon to BlokTrooper Socket.IO C2 195.201.104.53:6931/6936/6939

`UC_545_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.src) as src from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="195.201.104.53" AND All_Traffic.dest_port IN (6931,6936,6939) by All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "195.201.104.53"
| where RemotePort in (6931, 6936, 6939)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemotePort, LocalPort, Protocol
| order by Timestamp asc
```

### VSCode-family host fetching from raw.githubusercontent.com/BlokTrooper/extension path

`UC_545_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.src) as src from datamodel=Web.Web where Web.url="*raw.githubusercontent.com*" AND (Web.url="*BlokTrooper/extension*" OR Web.url="*BlokTrooper%2Fextension*") by Web.dest Web.url Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "raw.githubusercontent.com"
| where RemoteUrl has "BlokTrooper"
| where RemoteUrl has_any ("/scripts/linux.sh", "/scripts/mac.sh", "/scripts/windows.cmd", "/icons/", "/extension/")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Four-way node.exe -e fanout spawned from VSCode shell descendants (BlokTrooper stage-2)

`UC_545_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Processes.process) as cmds min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="node.exe" AND Processes.process="* -e *" AND Processes.parent_process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe") by Processes.dest Processes.user Processes.parent_process_name _time span=5m
| where count >= 4
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "node.exe"
| where ProcessCommandLine matches regex @"(?i)\s-e\s"
| where InitiatingProcessFileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe")
| where InitiatingProcessParentFileName in~ ("Code.exe","Code - Insiders.exe","VSCodium.exe","Cursor.exe","node.exe")
    or InitiatingProcessCommandLine has_any (@"\AppData\Local\Temp\", "/tmp/", "BlokTrooper", @"\.npm\")
| summarize NodeChildCount = count(), SampleCmds = make_set(ProcessCommandLine, 6), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, AccountName, InitiatingProcessParentFileName, bin(Timestamp, 5m)
| where NodeChildCount >= 4
| order by FirstSeen desc
```

### Non-browser process copying Chrome/Edge/Brave Login Data, Web Data, or wallet extension LevelDB state

`UC_545_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.process) as cmd from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("Login Data","Login Data For Account","Web Data","Local State","Cookies") OR Filesystem.file_path="*\\Local Extension Settings\\*") AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","brave.exe","opera.exe","MsMpEng.exe","explorer.exe","MsSense.exe") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("Login Data","Login Data For Account","Web Data","Local State","Cookies"))
    or (FolderPath has @"\Local Extension Settings\")
    or (PreviousFileName in~ ("Login Data","Login Data For Account","Web Data","Local State","Cookies"))
    or (PreviousFolderPath has @"\Local Extension Settings\")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","brave.exe","opera.exe","opera_gx.exe","explorer.exe","MsMpEng.exe","MsSense.exe","MpDefenderCoreService.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName, PreviousFolderPath, PreviousFileName
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

### Article-specific behavioural hunt — fast-draft Open VSX Extension Compromised by BlokTrooper

`UC_545_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — fast-draft Open VSX Extension Compromised by BlokTrooper ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/Keychains/login.keychain*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — fast-draft Open VSX Extension Compromised by BlokTrooper
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/Keychains/login.keychain"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `195.201.104.53`, `raw.githubusercontent.com/BlokTrooper/extension`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
