# [HIGH] Gremlin Stealer Stores C2 URLs and Exfiltration Paths in Encrypted Resource Sections

**Source:** Cyber Security News
**Published:** 2026-05-21
**Article:** https://cybersecuritynews.com/gremlin-stealer-stores-c2-urls/

## Threat Profile

Home Cyber Security News 
Gremlin Stealer Stores C2 URLs and Exfiltration Paths in Encrypted Resource Sections 
By Tushar Subhra Dutta 
May 21, 2026 




A newly analyzed variant of the Gremlin stealer malware has raised alarms by hiding its command-and-control (C2) addresses and data exfiltration paths inside encrypted resource sections of a compiled program. 
This approach makes the malware harder to detect through traditional scanning, allowing it to operate silently on infected systems b…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `194.87.92.109`
- **SHA256:** `2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b`
- **SHA256:** `9aab30a3190301016c79f8a7f8edf45ec088ceecad39926cfcf3418145f3d614`
- **SHA256:** `971198ff86aeb42739ba9381923d0bc6f847a91553ec57ea6bae5becf80f8759`
- **SHA256:** `ab0fa760bd037a95c4dee431e649e0db860f7cdad6428895b9a399b6991bf3cd`
- **SHA256:** `f76ba1a4650d8cafb6d3ff071688c5db6fd37e165050f03cece693826f51d346`
- **SHA256:** `a9f529a5cbc1f3ee80f785b22e0c472953e6cb226952218aecc7ab07ca328abd`
- **SHA256:** `691896c7be87e47f3e9ae914d76caaf026aaad0a1034e9f396c2354245215dc3`
- **SHA256:** `281b970f281dbea3c0e8cfc68b2e9939b253e5d3de52265b454d8f0f578768a2`
- **SHA256:** `9fda1ddb1acf8dd3685ec31b0b07110855832e3bed28a0f3b81c57fe7fe3ac20`
- **SHA256:** `d11938f14499de03d6a02b5e158782afd903460576e9227e0a15d960a2e9c02c`
- **SHA256:** `1bd0a200528c82c6488b4f48dd6dbc818d48782a2e25ccd22781c5718c3f62f5`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1074.001** — Data Staged: Local Data Staging
- **T1555** — Credentials from Password Stores

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Gremlin Stealer C2 beacon to 194.87.92.109/i.php

`UC_5_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (All_Traffic.dest="194.87.92.109" OR All_Traffic.dest_ip="194.87.92.109") by All_Traffic.src, All_Traffic.src_ip, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app, All_Traffic.user, All_Traffic.process_name, All_Traffic.url | `drop_dm_object_name(All_Traffic)` | eval c2_match=if(like(url, "%194.87.92.109/i.php%") OR dest="194.87.92.109", 1, 0) | where c2_match=1 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "194.87.92.109" or RemoteUrl has "194.87.92.109"
| extend ExfilPath = iff(RemoteUrl has "/i.php", "yes", "no")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteIP, RemotePort, RemoteUrl, ExfilPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Known Gremlin Stealer SHA256 sample execution

`UC_5_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b","9aab30a3190301016c79f8a7f8edf45ec088ceecad39926cfcf3418145f3d614","971198ff86aeb42739ba9381923d0bc6f847a91553ec57ea6bae5becf80f8759","ab0fa760bd037a95c4dee431e649e0db860f7cdad6428895b9a399b6991bf3cd","f76ba1a4650d8cafb6d3ff071688c5db6fd37e165050f03cece693826f51d346","a9f529a5cbc1f3ee80f785b22e0c472953e6cb226952218aecc7ab07ca328abd","691896c7be87e47f3e9ae914d76caaf026aaad0a1034e9f396c2354245215dc3","281b970f281dbea3c0e8cfc68b2e9939b253e5d3de52265b454d8f0f578768a2","9fda1ddb1acf8dd3685ec31b0b07110855832e3bed28a0f3b81c57fe7fe3ac20","d11938f14499de03d6a02b5e158782afd903460576e9227e0a15d960a2e9c02c","1bd0a200528c82c6488b4f48dd6dbc818d48782a2e25ccd22781c5718c3f62f5") by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.process_path, Processes.parent_process_name, Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let GremlinHashes = dynamic([
  "2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b",
  "9aab30a3190301016c79f8a7f8edf45ec088ceecad39926cfcf3418145f3d614",
  "971198ff86aeb42739ba9381923d0bc6f847a91553ec57ea6bae5becf80f8759",
  "ab0fa760bd037a95c4dee431e649e0db860f7cdad6428895b9a399b6991bf3cd",
  "f76ba1a4650d8cafb6d3ff071688c5db6fd37e165050f03cece693826f51d346",
  "a9f529a5cbc1f3ee80f785b22e0c472953e6cb226952218aecc7ab07ca328abd",
  "691896c7be87e47f3e9ae914d76caaf026aaad0a1034e9f396c2354245215dc3",
  "281b970f281dbea3c0e8cfc68b2e9939b253e5d3de52265b454d8f0f578768a2",
  "9fda1ddb1acf8dd3685ec31b0b07110855832e3bed28a0f3b81c57fe7fe3ac20",
  "d11938f14499de03d6a02b5e158782afd903460576e9227e0a15d960a2e9c02c",
  "1bd0a200528c82c6488b4f48dd6dbc818d48782a2e25ccd22781c5718c3f62f5"]);
union isfuzzy=true
(DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (GremlinHashes)
  | project Timestamp, Table="DeviceProcessEvents", DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath),
(DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (GremlinHashes)
  | project Timestamp, Table="DeviceFileEvents", DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, ProcessCommandLine=InitiatingProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath)
| order by Timestamp desc
```

### [LLM] IP-address-named ZIP archive created (Gremlin Stealer exfil pattern)

`UC_5_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.file_name="*.zip" by Filesystem.dest, Filesystem.user, Filesystem.file_name, Filesystem.file_path, Filesystem.process_name, Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | regex file_name="^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.zip$" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName endswith ".zip"
| where FileName matches regex @"^(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.zip$"
| where InitiatingProcessFileName !in~ ("7zG.exe","7z.exe","WinRAR.exe","Rar.exe","explorer.exe") // human archive tools occasionally rename — but rarely to a dotted-quad pattern
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, FileSize, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Discord token leveldb files read by non-Discord process

`UC_5_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Filesystem.file_name) as files min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Discord\\Local Storage\\leveldb\\*" OR Filesystem.file_path="*\\discordcanary\\Local Storage\\leveldb\\*" OR Filesystem.file_path="*\\discordptb\\Local Storage\\leveldb\\*") Filesystem.process_name!="Discord.exe" Filesystem.process_name!="DiscordCanary.exe" Filesystem.process_name!="DiscordPTB.exe" Filesystem.process_name!="Update.exe" by Filesystem.dest, Filesystem.user, Filesystem.process_name, Filesystem.process_path, Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has @"\Discord\Local Storage\leveldb"
   or FolderPath has @"\discordcanary\Local Storage\leveldb"
   or FolderPath has @"\discordptb\Local Storage\leveldb"
| where InitiatingProcessFileName !in~ ("Discord.exe","DiscordCanary.exe","DiscordPTB.exe","Update.exe","DiscordSetup.exe","DiscordCrashHandler.exe")
| where InitiatingProcessAccountName !endswith "$"
| summarize FilesTouched = dcount(FileName), Files = make_set(FileName, 25), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), AnyCmd = any(InitiatingProcessCommandLine), AnySHA = any(InitiatingProcessSHA256), AnyFolder = any(InitiatingProcessFolderPath) by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName
| where FilesTouched >= 1
| order by LastSeen desc
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

### Article-specific behavioural hunt — Gremlin Stealer Stores C2 URLs and Exfiltration Paths in Encrypted Resource Sect

`UC_5_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Gremlin Stealer Stores C2 URLs and Exfiltration Paths in Encrypted Resource Sect ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("217.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("217.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Gremlin Stealer Stores C2 URLs and Exfiltration Paths in Encrypted Resource Sect
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("217.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("217.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `194.87.92.109`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b`, `9aab30a3190301016c79f8a7f8edf45ec088ceecad39926cfcf3418145f3d614`, `971198ff86aeb42739ba9381923d0bc6f847a91553ec57ea6bae5becf80f8759`, `ab0fa760bd037a95c4dee431e649e0db860f7cdad6428895b9a399b6991bf3cd`, `f76ba1a4650d8cafb6d3ff071688c5db6fd37e165050f03cece693826f51d346`, `a9f529a5cbc1f3ee80f785b22e0c472953e6cb226952218aecc7ab07ca328abd`, `691896c7be87e47f3e9ae914d76caaf026aaad0a1034e9f396c2354245215dc3`, `281b970f281dbea3c0e8cfc68b2e9939b253e5d3de52265b454d8f0f578768a2` _(+3 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
