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
- **T1059** — Command and Scripting Interpreter
- **T1055** — Process Injection
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1114.001** — Email Collection: Local Email Collection
- **T1005** — Data from Local System
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567** — Exfiltration Over Web Service
- **T1559** — Inter-Process Communication
- **T1559.001** — Component Object Model

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Kazuar (Secret Blizzard / Turla) modular backdoor execution by SHA256

`UC_27_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where Processes.process_hash IN ("69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85") by Processes.dest Processes.user Processes.process_name Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let KazuarHashes = dynamic(["69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (KazuarHashes) or InitiatingProcessSHA256 in (KazuarHashes)
    | project Timestamp, DeviceName, AccountName, ActionType="ProcessExec", FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (KazuarHashes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, ActionType="DllLoaded", FileName, FolderPath, SHA256, ProcessCommandLine="", InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (KazuarHashes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine="", InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### [LLM] Non-Outlook process accessing Outlook OST/PST mailbox stores (Kazuar Worker MAPI harvest)

`UC_27_3` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.pst" OR Filesystem.file_name="*.ost" OR Filesystem.file_path="*\\Microsoft\\Outlook\\*") AND Filesystem.process_name!="outlook.exe" AND Filesystem.process_name!="OUTLOOK.EXE" AND Filesystem.process_name!="searchindexer.exe" AND Filesystem.process_name!="searchprotocolhost.exe" AND Filesystem.process_name!="msmpeng.exe" AND Filesystem.process_name!="backupexec.exe" AND Filesystem.process_name!="veeam.backup.shell.exe" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)` | where count > 0
```

**Defender KQL:**
```kql
let MailClients = dynamic(["outlook.exe","searchindexer.exe","searchprotocolhost.exe","msmpeng.exe","mssense.exe","backupexec.exe","veeam.backup.shell.exe","hyperbac.exe"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName endswith ".ost" or FileName endswith ".pst" or FolderPath has @"\Microsoft\Outlook\"
| where InitiatingProcessFileName !in~ (MailClients)
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFolderPath !startswith @"C:\Program Files\Microsoft Office\"
  and InitiatingProcessFolderPath !startswith @"C:\Program Files (x86)\Microsoft Office\"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), FilesTouched=dcount(FileName), Files=make_set(FileName, 25), Actions=make_set(ActionType, 10) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by FirstSeen desc
```

### [LLM] Non-mail-client process posting to Exchange Web Services (Kazuar Bridge module C2)

`UC_27_4` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as process from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url="*/EWS/Exchange.asmx*" OR All_Traffic.url="*/ews/exchange.asmx*" OR All_Traffic.dest="outlook.office365.com" OR All_Traffic.dest="outlook.office.com") AND All_Traffic.app!="outlook.exe" AND All_Traffic.app!="OUTLOOK.EXE" AND All_Traffic.app!="msedge.exe" AND All_Traffic.app!="chrome.exe" AND All_Traffic.app!="firefox.exe" AND All_Traffic.app!="teams.exe" AND All_Traffic.app!="ms-teams.exe" AND All_Traffic.app!="olk.exe" AND All_Traffic.app!="mapisrvr.exe" by All_Traffic.src All_Traffic.user All_Traffic.app | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let MailClients = dynamic(["outlook.exe","olk.exe","teams.exe","ms-teams.exe","msedge.exe","chrome.exe","firefox.exe","brave.exe","safari.exe","mapisrvr.exe","hxoutlook.exe","hxtsr.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where (RemoteUrl has "/EWS/Exchange.asmx" or RemoteUrl has "/ews/exchange.asmx")
      or (RemoteUrl endswith "outlook.office365.com" or RemoteUrl endswith "outlook.office.com")
| where InitiatingProcessFileName !in~ (MailClients)
| where InitiatingProcessAccountName !endswith "$"
| summarize Connections=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), URLs=make_set(RemoteUrl, 20), DestIPs=make_set(RemoteIP, 20) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| where Connections >= 1
| order by FirstSeen desc
```

### [LLM] Mailslot creation by non-system process (Kazuar Kernel-module P2P IPC)

`UC_27_5` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\\\.\\mailslot\\*" AND Filesystem.process_name!="services.exe" AND Filesystem.process_name!="svchost.exe" AND Filesystem.process_name!="lsass.exe" AND Filesystem.process_name!="spoolsv.exe" AND Filesystem.process_name!="winlogon.exe" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let SystemBins = dynamic(["services.exe","svchost.exe","lsass.exe","spoolsv.exe","winlogon.exe","smss.exe","wininit.exe","csrss.exe","system"]);
let PipeFromDeviceEvents = DeviceEvents
  | where Timestamp > ago(7d)
  | where ActionType in ("NamedPipeEvent","FileCreated","PipeCreated")
  | extend AF = parse_json(AdditionalFields)
  | extend PipeOrMailslot = coalesce(tostring(AF.FileName), tostring(AF.PipeName), FileName, FolderPath)
  | where PipeOrMailslot has @"\mailslot\" or PipeOrMailslot has @"\Mailslot\"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, PipeOrMailslot;
let PipeFromFileEvents = DeviceFileEvents
  | where Timestamp > ago(7d)
  | where FolderPath has @"\mailslot\" or FileName startswith @"\\.\mailslot\" or FolderPath startswith @"\\.\mailslot\"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, PipeOrMailslot=strcat(FolderPath,"\\",FileName);
union PipeFromDeviceEvents, PipeFromFileEvents
| where InitiatingProcessFileName !in~ (SystemBins)
| where AccountName !endswith "$" or InitiatingProcessFolderPath !startswith @"C:\Windows\System32\"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Mailslots=make_set(PipeOrMailslot, 20), HostsSeen=dcount(DeviceName) by InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256
| order by HostsSeen desc, FirstSeen desc
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

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
