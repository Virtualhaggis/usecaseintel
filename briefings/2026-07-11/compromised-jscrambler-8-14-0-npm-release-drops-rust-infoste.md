# [CRIT] Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install

**Source:** The Hacker News
**Published:** 2026-07-11
**Article:** https://thehackernews.com/2026/07/compromised-jscrambler-8140-npm-release.html

## Threat Profile

Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install 
 Swati Khandelwal  Jul 11, 2026 Software Supply Chain / Malware 
The jscrambler npm package was compromised, and simply installing its 8.14.0 release runs an infostealer on your machine. Published on July 11, 2026, the malicious version carries a preinstall hook that drops and executes a native binary, one build each for Windows, macOS, and Linux.
Socket flagged the release  six minutes after it was published . If…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `37.27.122.124`
- **IPv4 (defanged):** `57.128.246.79`
- **SHA256:** `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`
- **SHA256:** `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`
- **SHA256:** `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`
- **SHA256:** `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`
- **SHA256:** `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1053.005** — Scheduled Task
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1543.001** — Persistence (article-specific)
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1204.003** — User Execution: Malicious Package
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm install of trojanized jscrambler@8.14.0 supply-chain package

`UC_0_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*jscrambler@8.14.0*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "jscrambler@8.14.0"
| where FileName in~ ("node.exe","npm.exe","npm.cmd","npx.exe","yarn.exe","pnpm.exe","cmd.exe","powershell.exe","pwsh.exe","bash","sh")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Known jscrambler infostealer file/payload SHA256 dropped or executed

`UC_0_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60","a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86","fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd","b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903","c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let badHashes = dynamic(["a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60","a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86","fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd","b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903","c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd"]);
union
  (DeviceFileEvents | where Timestamp > ago(30d) | where SHA256 in~ (badHashes) | project Timestamp, DeviceName, Kind="FileEvent", ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceProcessEvents | where Timestamp > ago(30d) | where SHA256 in~ (badHashes) | project Timestamp, DeviceName, Kind="ProcessCreated", ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### npm preinstall hook: Node spawns hidden temp binary detached (jscrambler loader)

`UC_0_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","npm.exe","node") (Processes.parent_process="*setup.js*" OR Processes.parent_process="*preinstall*") (Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*/tmp/*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","node")
| where InitiatingProcessCommandLine has_any ("setup.js","preinstall","intro.js")
| where FolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\", @"\Windows\Temp\", "/tmp/", "/var/tmp/")
| where FileName startswith "." or ProcessVersionInfoCompanyName == ""
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Infostealer C2 beacon to jscrambler campaign IPs / Tor bootstrap

`UC_0_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("37.27.122.124","57.128.246.79") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("37.27.122.124","57.128.246.79") or RemoteUrl in~ ("check.torproject.org","archive.torproject.org")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### Hidden every-minute scheduled task written by temp-directory binary (jscrambler persistence)

`UC_0_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name=schtasks.exe Processes.process="*/create*" (Processes.process="*/sc minute*" OR Processes.process="*/sc MINUTE*") (Processes.process="*/mo 1*" OR Processes.process="*\\Temp\\*" OR Processes.process="*\\AppData\\Local\\Temp\\*") by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
| where InitiatingProcessFolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\", @"\Windows\Temp\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Temp-directory binary fans out across browser/cloud/AI-tool secret stores

`UC_0_13` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Filesystem.file_path) as stores values(Filesystem.file_path) as paths min(_time) as firstTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Google\\Chrome\\User Data*" OR Filesystem.file_path="*\\Microsoft\\Edge\\User Data*" OR Filesystem.file_path="*key4.db*" OR Filesystem.file_path="*Login Data*" OR Filesystem.file_path="*\\.aws*" OR Filesystem.file_path="*\\Bitwarden*" OR Filesystem.file_path="*\\Claude*" OR Filesystem.file_path="*\\Cursor*" OR Filesystem.file_path="*\\Windsurf*" OR Filesystem.file_path="*\\Zed*" OR Filesystem.file_path="*\\MetaMask*" OR Filesystem.file_path="*\\Exodus*") by Filesystem.dest Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | where stores >= 3
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFolderPath has_any (@"\Temp\", @"\AppData\Local\Temp\", @"\Windows\Temp\", "/tmp/", "/var/tmp/")
| where FolderPath has_any (@"\Google\Chrome\User Data", @"\Microsoft\Edge\User Data", @"\Mozilla\Firefox\Profiles", "key4.db", "Login Data", "Cookies", "Web Data", @"\.aws", @"\.azure", "gcloud", @"\Bitwarden", @"\Claude", @"\Cursor", @"\Windsurf", @"\.codeium", @"\Zed", @"\Code\User", @"\Exodus", "MetaMask", @"\discord", @"\Slack")
| summarize StoresTouched = dcount(FolderPath), Samples = make_set(FolderPath, 25), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath
| where StoresTouched >= 3
| order by StoresTouched desc
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

### Article-specific behavioural hunt — Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install

`UC_0_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("setup.js","intro.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/LaunchAgents*" OR Filesystem.file_name IN ("setup.js","intro.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Compromised jscrambler 8.14.0 npm Release Drops Rust Infostealer During Install
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("setup.js", "intro.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/LaunchAgents") or FileName in~ ("setup.js", "intro.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `37.27.122.124`, `57.128.246.79`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a742de963f14a92d24ebcbc7b44ac867e23a20d31d1b0094a13a4f83287f4e60`, `a41a523ef9517aab37ed6eea0ec881821bdcb7aefcb5c5f603adc7907f868c86`, `fbbcf4d8f98168f78f5c0c47a9ae56d59ec8ac84a7c9ca6b797fedfb8d62d2bd`, `b7ca95d1b23c8e67416a25cedf741de0917c2096bbc9d24649eea7853d054903`, `c8fd47d36bdf7c825378593ab82ed8c24d1dc52e26b507812393e24e1d5201fd`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
