# [HIGH] A laughing RAT: CrystalX combines spyware, stealer, and prankware features

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-01
**Article:** https://securelist.com/crystalx-rat-with-prankware-features/119283/

## Threat Profile

Table of Contents
Introduction 
Technical details 
Background 
The builder and anti-debug features 
Stealer capabilities 
Keylogger & clipper 
Remote access 
Prank commands 
Conclusions 
Indicators of Compromise 
Authors
GReAT 
Introduction 
In March 2026, we discovered an active campaign promoting previously unknown malware in private Telegram chats. The Trojan was offered as a MaaS (malware‑as‑a‑service) with three subscription tiers. It caught our attention because of its extensive arsenal of…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `webcrystal.lol`
- **Domain (defanged):** `webcrystal.sbs`
- **Domain (defanged):** `crystalxrat.top`
- **MD5:** `47ACCB0ECFE8CCD466752DDE1864F3B0`
- **MD5:** `2DBE6DE177241C144D06355C381B868C`
- **MD5:** `49C74B302BFA32E45B7C1C5780DD0976`
- **MD5:** `88C60DF2A1414CBF24430A74AE9836E0`
- **MD5:** `E540E9797E3B814BFE0A82155DFE135D`
- **MD5:** `1A68AE614FB2D8875CB0573E6A721B46`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1005** — Data from Local System
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1140** — Deobfuscate/Decode Files or Information
- **T1074.001** — Local Data Staging
- **T1546** — Event Triggered Execution
- **T1565.002** — Transmitted Data Manipulation
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1095** — Non-Application Layer Protocol
- **T1571** — Non-Standard Port

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where FolderPath has_any ("\Ethereum\keystore\","\Bitcoin\","\Exodus\","\Electrum\wallets\","\MetaMask\","\Phantom\","\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Article-specific behavioural hunt — A laughing RAT: CrystalX combines spyware, stealer, and prankware features

`UC_143_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — A laughing RAT: CrystalX combines spyware, stealer, and prankware features ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("content.js") OR Processes.process_path="*%LOCALAPPDATA%\Microsoft\Edge\ExtSvc*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%LOCALAPPDATA%\Microsoft\Edge\ExtSvc*" OR Filesystem.file_name IN ("content.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — A laughing RAT: CrystalX combines spyware, stealer, and prankware features
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("content.js") or FolderPath has_any ("%LOCALAPPDATA%\Microsoft\Edge\ExtSvc"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%LOCALAPPDATA%\Microsoft\Edge\ExtSvc") or FileName in~ ("content.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] CrystalX RAT ChromeElevator drop to %TEMP%\svc[N].exe with co[N] staging dir

`UC_143_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as creator from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*\\Temp\\svc*.exe","*\\Temp\\co*\\*") by Filesystem.dest Filesystem.user _time span=5m | `drop_dm_object_name(Filesystem)` | rex field=file_path "(?i)\\\\Temp\\\\(?<artifact>(svc\d+\.exe|co\d+))" | stats count dc(artifact) as distinct_artifacts values(file_path) as paths values(creator) as creator min(firstTime) as firstTime max(lastTime) as lastTime by dest user | where distinct_artifacts>=2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let window = 10m;
let svcDrops = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FolderPath has "\\Temp\\" and FileName matches regex @"(?i)^svc\d+\.exe$"
| project DeviceId, DeviceName, Svctime=Timestamp, SvcFile=FolderPath, SvcCreator=InitiatingProcessFileName;
let coDirs = DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath matches regex @"(?i)\\Temp\\co\d+\\"
| project DeviceId, CoTime=Timestamp, CoPath=FolderPath, CoCreator=InitiatingProcessFileName;
svcDrops
| join kind=inner coDirs on DeviceId
| where abs(datetime_diff('second', Svctime, CoTime)) <= 600
| project DeviceName, DeviceId, Svctime, SvcFile, CoPath, SvcCreator, CoCreator
| summarize FirstSeen=min(Svctime), Drops=make_set(SvcFile,5), StagingDirs=make_set(CoPath,5), Creators=make_set(SvcCreator,5) by DeviceName, DeviceId
```

### [LLM] CrystalX clipper extension dropped to %LOCALAPPDATA%\Microsoft\Edge\ExtSvc

`UC_143_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path values(Filesystem.process_name) as writer from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\AppData\\Local\\Microsoft\\Edge\\ExtSvc\\*" (Filesystem.file_name="content.js" OR Filesystem.file_name="manifest.json") by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | join type=outer dest [| tstats `summariesonly` values(Processes.process) as cdp_cmdline from datamodel=Endpoint.Processes where (Processes.process_name=chrome.exe OR Processes.process_name=msedge.exe) Processes.process IN ("*--remote-debugging-port=*","*--remote-debugging-pipe*") by Processes.dest | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let extDrop = DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FolderPath has @"\AppData\Local\Microsoft\Edge\ExtSvc"
| where FileName in~ ("content.js","manifest.json")
| project DropTime=Timestamp, DeviceId, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256;
let cdpLaunch = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("chrome.exe","msedge.exe")
| where ProcessCommandLine has_any ("--remote-debugging-port","--remote-debugging-pipe")
| project CdpTime=Timestamp, DeviceId, BrowserCmd=ProcessCommandLine;
extDrop
| join kind=leftouter cdpLaunch on DeviceId
| where isnull(CdpTime) or abs(datetime_diff('minute', DropTime, CdpTime)) <= 30
| summarize FirstSeen=min(DropTime), Files=make_set(FileName), Writers=make_set(InitiatingProcessFileName), CdpCmd=make_set(BrowserCmd,3) by DeviceName, DeviceId, FolderPath
```

### [LLM] CrystalX RAT C2 beaconing to webcrystal[.]lol / webcrystal[.]sbs / crystalxrat[.]top

`UC_143_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution.DNS where DNS.query IN ("webcrystal.lol","*.webcrystal.lol","webcrystal.sbs","*.webcrystal.sbs","crystalxrat.top","*.crystalxrat.top") by DNS.dest | `drop_dm_object_name(DNS)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_host IN ("webcrystal.lol","webcrystal.sbs","crystalxrat.top") OR All_Traffic.url="*webcrystal.*" OR All_Traffic.url="*crystalxrat.top*" by All_Traffic.dest_host All_Traffic.app] | append [| tstats `summariesonly` count values(Processes.process) as process values(Processes.process_hash) as md5 from datamodel=Endpoint.Processes where Processes.process_hash IN ("47ACCB0ECFE8CCD466752DDE1864F3B0","2DBE6DE177241C144D06355C381B868C","49C74B302BFA32E45B7C1C5780DD0976","88C60DF2A1414CBF24430A74AE9836E0","E540E9797E3B814BFE0A82155DFE135D","1A68AE614FB2D8875CB0573E6A721B46") by Processes.dest Processes.user | `drop_dm_object_name(Processes)`] | stats values(*) as * min(firstTime) as firstTime max(lastTime) as lastTime by src dest | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let badDomains = dynamic(["webcrystal.lol","webcrystal.sbs","crystalxrat.top"]);
let badMD5 = dynamic(["47ACCB0ECFE8CCD466752DDE1864F3B0","2DBE6DE177241C144D06355C381B868C","49C74B302BFA32E45B7C1C5780DD0976","88C60DF2A1414CBF24430A74AE9836E0","E540E9797E3B814BFE0A82155DFE135D","1A68AE614FB2D8875CB0573E6A721B46"]);
let net = DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (badDomains) or tostring(parse_url(RemoteUrl)["Host"]) in~ (badDomains)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Source="DeviceNetworkEvents";
let hashHits = DeviceProcessEvents
| where Timestamp > ago(30d)
| where tolower(MD5) in (badMD5) or tolower(InitiatingProcessMD5) in (badMD5)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName=FileName, InitiatingProcessCommandLine=ProcessCommandLine, RemoteUrl="", RemoteIP="", RemotePort=int(null), Source="DeviceProcessEvents-MD5";
let fileHits = DeviceFileEvents
| where Timestamp > ago(30d)
| where tolower(MD5) in (badMD5)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine=FolderPath, RemoteUrl="", RemoteIP="", RemotePort=int(null), Source="DeviceFileEvents-MD5";
union net, hashHits, fileHits
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Sources=make_set(Source), URLs=make_set(RemoteUrl,5), IPs=make_set(RemoteIP,5), Procs=make_set(InitiatingProcessFileName,5) by DeviceName, DeviceId
| order by FirstSeen asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `webcrystal.lol`, `webcrystal.sbs`, `crystalxrat.top`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `47ACCB0ECFE8CCD466752DDE1864F3B0`, `2DBE6DE177241C144D06355C381B868C`, `49C74B302BFA32E45B7C1C5780DD0976`, `88C60DF2A1414CBF24430A74AE9836E0`, `E540E9797E3B814BFE0A82155DFE135D`, `1A68AE614FB2D8875CB0573E6A721B46`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
