# [HIGH] Russian hackers turn Kazuar backdoor into modular P2P botnet

**Source:** BleepingComputer
**Published:** 2026-05-16
**Article:** https://www.bleepingcomputer.com/news/security/russian-hackers-turn-kazuar-backdoor-into-modular-p2p-botnet/

## Threat Profile

Russian hackers turn Kazuar backdoor into modular P2P botnet 
By Bill Toulas 
May 16, 2026
10:15 AM
0 
The Russian hacker group Secret Blizzard has developed its long-running Kazuar backdoor into a modular peer-to-peer (P2P) botnet designed for long-term persistence, stealth, and data collection.
Secret Blizzard, whose activity overlaps that of Turla, Uroburos, and Venomous Bear, has been associated with the Russian intelligence service (FSB) and is known for targeting government and diplomatic …

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4`
- **SHA256:** `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9`
- **SHA256:** `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d`
- **SHA256:** `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1027** — Obfuscated Files or Information
- **T1559** — Inter-Process Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1570** — Lateral Tool Transfer
- **T1021.002** — Remote Services: SMB/Windows Admin Shares

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Kazuar Kernel/Bridge/Worker module hash execution (Secret Blizzard 2026 variant)

`UC_8_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85") by Processes.dest Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let KazuarHashes = dynamic(["69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85"]);
union isfuzzy=true
( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (KazuarHashes) or InitiatingProcessSHA256 in (KazuarHashes)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256, Source="DeviceProcessEvents" ),
( DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (KazuarHashes)
    | project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, Source="DeviceImageLoadEvents" )
| order by Timestamp desc
```

### [LLM] Kazuar Bridge module Exchange Web Services C2 from non-mail-client process

`UC_8_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.url) as urls values(Web.user) as user values(Web.dest) as remote_host min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/EWS/Exchange.asmx*" OR Web.url="*/ews/exchange*" OR Web.url="*/EWS/Subscribe*" OR Web.url="*/EWS/Services.wsdl*") AND NOT (Web.process_name IN ("OUTLOOK.EXE","outlook.exe","hxoutlook.exe","olk.exe","Teams.exe","msteams.exe","lync.exe","communicator.exe","WINWORD.EXE","EXCEL.EXE","thunderbird.exe","mailclient.exe","explorer.exe")) by Web.src Web.process_name Web.process_hash | `drop_dm_object_name(Web)` | where count > 3 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MailClients = dynamic(["outlook.exe","hxoutlook.exe","olk.exe","hxtsr.exe","hxmail.exe","teams.exe","ms-teams.exe","lync.exe","communicator.exe","thunderbird.exe","em_executive.exe","em_aclient.exe","officeclicktorun.exe","winword.exe","excel.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any ("/EWS/Exchange.asmx", "/ews/exchange", "/EWS/Subscribe", "/EWS/Services.wsdl", "/ews/services")
| where tolower(InitiatingProcessFileName) !in (MailClients)
| where InitiatingProcessFileName !endswith "officeclicktorun.exe"
| where InitiatingProcessAccountName !endswith "$"
| summarize ConnectionCount = count(), DistinctUrls = dcount(RemoteUrl), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleUrls = make_set(RemoteUrl, 5), SampleCmds = make_set(InitiatingProcessCommandLine, 3) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, RemoteIP
| where ConnectionCount >= 3
| order by FirstSeen desc
```

### [LLM] Kazuar Kernel leader–peer IPC via mailslots and named pipes between non-server endpoints

`UC_8_4` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(All_Traffic.dest_ip) as peer_ips values(All_Traffic.src_ip) as src_ips dc(All_Traffic.dest_ip) as peer_count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=445 AND All_Traffic.transport="tcp" AND NOT (All_Traffic.dest_category="server" OR All_Traffic.dest_category="domain_controller" OR All_Traffic.src_category="server") by All_Traffic.src host_subnet=All_Traffic.src bin span=30m _time | join type=outer host_subnet [ search index=sysmon EventCode IN (17,18) PipeName="*\\mailslot\\*" OR PipeName="*\\Kazuar*" OR PipeName="*\\Win*Msg*" | stats values(PipeName) as pipes by host ] | where peer_count >= 2 AND isnotnull(pipes)
```

**Defender KQL:**
```kql
let RecentHours = 24h;
let PipeEvents = DeviceEvents
    | where Timestamp > ago(RecentHours)
    | where ActionType in ("NamedPipeEvent", "PipeCreated", "PipeConnected")
    | extend AF = parse_json(AdditionalFields)
    | extend PipeName = tostring(coalesce(AF.PipeName, AF.PipePath))
    | where isnotempty(PipeName)
    | where PipeName has_any ("\\mailslot\\", "messag", "kernel", "bridge", "worker")
           or PipeName matches regex @"\\[a-f0-9]{8,32}$"
    | where InitiatingProcessAccountName !endswith "$"
    | where InitiatingProcessFolderPath !startswith @"C:\Windows\System32\"
    | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, PipeName;
let CrossHostSMB = DeviceNetworkEvents
    | where Timestamp > ago(RecentHours)
    | where RemotePort == 445 and Protocol == "Tcp"
    | where ipv4_is_private(LocalIP) and ipv4_is_private(RemoteIP)
    | join kind=leftanti (
        DeviceInfo
        | where DeviceCategory in ("Server","DomainController") or IsInternetFacing == true
        | distinct DeviceName
      ) on $left.RemoteDeviceName == $right.DeviceName
    | where InitiatingProcessAccountName !endswith "$"
    | summarize PeerCount = dcount(RemoteIP), Peers = make_set(RemoteIP, 20), ConnCount = count() by DeviceName, DeviceId, InitiatingProcessFileName, bin(Timestamp, 1h)
    | where PeerCount >= 2 and ConnCount >= 4;
PipeEvents
| join kind=inner CrossHostSMB on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessCommandLine, PipeName, PeerCount, Peers, ConnCount
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4`, `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9`, `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d`, `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
