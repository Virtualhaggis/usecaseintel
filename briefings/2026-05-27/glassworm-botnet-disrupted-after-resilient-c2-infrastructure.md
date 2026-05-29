# [HIGH] Glassworm botnet disrupted after resilient C2 infrastructure takedown

**Source:** BleepingComputer
**Published:** 2026-05-27
**Article:** https://www.bleepingcomputer.com/news/security/glassworm-botnet-disrupted-after-resilient-c2-infrastructure-takedown/

## Threat Profile

Glassworm botnet disrupted after resilient C2 infrastructure takedown 
By Ionut Ilascu 
May 27, 2026
09:28 AM
0 
The Glassworm botnet targeting developers in software supply-chain attacks has been disrupted after researchers took down its resilient command-and-control infrastructure relying on Solana blockchain transactions and the BitTorrent DHT network.
​In a coordinated operation conducted  yesterday, CrowdStrike, Google, and The Shadowserver Foundation cut off the botnet operators’ access to…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1195.002** — Compromise Software Supply Chain
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1041** — Exfiltration Over C2 Channel
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1102.002** — Web Service: Bidirectional Communication
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1176** — Browser Extensions
- **T1546.006** — Event Triggered Execution: LSASS Driver
- **T1555** — Credentials from Password Stores
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1083** — File and Directory Discovery
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Post-takedown beacon to CrowdStrike Glassworm sinkhole 164.92.88.210

`UC_45_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.src) as src_endpoint values(All_Traffic.user) as user values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="164.92.88.210" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "164.92.88.210"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### [LLM] Outbound connection to Glassworm operator VPS C2 infrastructure

`UC_45_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("217.69.3.218","199.247.10.166","140.82.52.31","199.247.13.106") by All_Traffic.src All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GlasswormC2 = dynamic(["217.69.3.218","199.247.10.166","140.82.52.31","199.247.13.106"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP in (GlasswormC2)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] VS Code / Node / Cursor process resolving Solana mainnet RPC (Glassworm C2 channel)

`UC_45_4` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answers from datamodel=Network_Resolution.DNS where DNS.query IN ("api.mainnet-beta.solana.com","*.solana.com","solana-api.projectserum.com","rpc.ankr.com") by DNS.query DNS.src | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("mainnet-beta.solana.com", "solana-api.projectserum.com", "api.devnet.solana.com", "rpc.ankr.com/solana", ".solana.com")
| where InitiatingProcessFileName in~ ("code.exe","node.exe","cursor.exe","code - insiders.exe","electron.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Developer endpoint emitting BitTorrent DHT bootstrap traffic from non-torrent process

`UC_45_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("code.exe","node.exe","cursor.exe","electron.exe") AND (All_Traffic.dest_port IN (6881,6882,6883,6884,6885,6886,6887,6888,6889) OR All_Traffic.dest IN ("router.bittorrent.com","dht.transmissionbt.com","router.utorrent.com","dht.libtorrent.org")) by All_Traffic.src All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let DhtBootstrap = dynamic(["router.bittorrent.com","dht.transmissionbt.com","router.utorrent.com","dht.libtorrent.org","router.silotis.us"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("code.exe","node.exe","cursor.exe","electron.exe","code - insiders.exe")
| where (RemoteUrl has_any (DhtBootstrap)) or (Protocol == "Udp" and RemotePort between (6881 .. 6889))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] IDE / Node process resolving calendar.google.com as Glassworm C2 dead-drop

`UC_45_6` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.url) as url from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("code.exe","node.exe","cursor.exe","electron.exe") AND All_Traffic.dest IN ("calendar.google.com","www.googleapis.com","clients6.google.com") by All_Traffic.src All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("code.exe","node.exe","cursor.exe","electron.exe","code - insiders.exe")
| where RemoteUrl has_any ("calendar.google.com", "www.googleapis.com/calendar", "clients6.google.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| order by Timestamp desc
```

### [LLM] Trojanized Glassworm VS Code / OpenVSX extension package files on developer host

`UC_45_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\.vscode\\extensions\\*" AND Filesystem.file_name IN ("codejoy-vscode-extension*","vscode-theme-seti-folder*","serenity-dsl-syntaxhighlight*","rust-doc-viewer*","dark-theme-sm*","git-worktree-menu*","better-nunjucks*","recoil*") by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GlasswormPkgs = dynamic(["codejoy-vscode-extension","vscode-theme-seti-folder","serenity-dsl-syntaxhighlight","rust-doc-viewer","dark-theme-sm","git-worktree-menu","better-nunjucks","recoil"]);
DeviceFileEvents
| where Timestamp > ago(90d)
| where FolderPath has_any (@"\.vscode\extensions\", "/.vscode-server/extensions/", "/.vscode/extensions/")
| where FolderPath has_any (GlasswormPkgs) or FileName has_any (GlasswormPkgs)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, ActionType, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] VS Code child process reads wallet / dev-credential files (Glassworm credential theft)

`UC_45_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("code.exe","node.exe","electron.exe","cursor.exe") AND Filesystem.file_path IN ("*\\.aws\\credentials","*\\.ssh\\id_rsa*","*\\.ssh\\id_ed25519*","*\\.npmrc","*\\.git-credentials","*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn\\*","*wallet.dat","*\\Roaming\\Exodus\\*","*\\Roaming\\Electrum\\wallets\\*") by Filesystem.dest Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let CredTargets = dynamic([
    @"\.aws\credentials", @"\.ssh\id_rsa", @"\.ssh\id_ed25519", @"\.npmrc", @"\.git-credentials",
    @"\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn", // MetaMask
    @"\Local Extension Settings\ejbalbakoplchlghecdalmeeeajnimhm", // MetaMask (Edge)
    "wallet.dat", @"\Exodus\exodus.wallet", @"\Electrum\wallets"
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileOpened","FileRead","FileCreated","FileRenamed","FileModified")
| where InitiatingProcessFileName in~ ("code.exe","node.exe","electron.exe","cursor.exe","code - insiders.exe")
| where FolderPath has_any (CredTargets) or FileName has_any (CredTargets)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName
| order by Timestamp desc
```

### [LLM] First-time install of any Glassworm-named extension across the org (baseline anti-join)

`UC_45_9` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.dest) as dest values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\.vscode\\extensions\\*" by Filesystem.file_path | `drop_dm_object_name(Filesystem)` | rex field=file_path "\\\\extensions\\\\(?<pkg>[^\\\\]+)" | search pkg IN ("codejoy-vscode-extension*","vscode-theme-seti-folder*","serenity-dsl-syntaxhighlight*","rust-doc-viewer*","dark-theme-sm*","git-worktree-menu*","better-nunjucks*","recoil*") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GlasswormPkgs = dynamic(["codejoy-vscode-extension","vscode-theme-seti-folder","serenity-dsl-syntaxhighlight","rust-doc-viewer","dark-theme-sm","git-worktree-menu","better-nunjucks","recoil"]);
let Baseline = DeviceFileEvents
    | where Timestamp between (ago(90d) .. ago(7d))
    | where FolderPath has @"\.vscode\extensions\"
    | where FolderPath has_any (GlasswormPkgs)
    | summarize by DeviceName;
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has @"\.vscode\extensions\"
| where FolderPath has_any (GlasswormPkgs)
| join kind=leftanti Baseline on DeviceName
| summarize FirstSeen = min(Timestamp), arg_min(Timestamp, *) by DeviceName, InitiatingProcessAccountName
| project FirstSeen, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256
| order by FirstSeen desc
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


## Why this matters

Severity classified as **HIGH** based on: 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
