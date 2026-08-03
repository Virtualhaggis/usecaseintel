# [HIGH] Amazon links Debug, Chalk NPM supply-chain attacks to North Korean hackers

**Source:** BleepingComputer
**Published:** 2026-07-30
**Article:** https://www.bleepingcomputer.com/news/security/amazon-links-debug-chalk-npm-supply-chain-attacks-to-north-korean-hackers/

## Threat Profile

Amazon links Debug, Chalk NPM supply-chain attacks to North Korean hackers 
By Bill Toulas 
July 30, 2026
02:13 PM
0 
Amazon linked multiple high-profile open-source software supply chain attacks targeting the Node Package Manager (npm) ecosystem to North Korean hackers.
The cloud computing giant linked the compromises of the typo-crypto, debug, chalk, and axios libraries to the Sapphire Sleet threat actor, also known as BlueNoroff and Stardust Chollima.
Initial activity started with trojanizing…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `216.74.123.126`
- **Domain (defanged):** `npmjs.store`
- **SHA256:** `24604384b0e748ada07923630b3d037489e696284a98c4409fb9b6763565571f`
- **SHA256:** `2014d09c7ded74d89c885b5f11693865224116f1b25df9330e61fe528f419d73`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Sapphire Sleet npm supply-chain C2 egress to npmjs.store / 216.74.123.126

`UC_49_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="216.74.123.126" OR All_Traffic.dest_host="npmjs.store" OR All_Traffic.url="*npmjs.store*") by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let c2ip = "216.74.123.126";
let c2dom = "npmjs.store";
union
(DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == c2ip or RemoteUrl has c2dom
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort),
(DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has c2dom or AdditionalFields has c2dom
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl)
| order by Timestamp desc
```

### Sapphire Sleet trojanized npm payload hashes on disk / in-execution

`UC_49_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_hash="24604384b0e748ada07923630b3d037489e696284a98c4409fb9b6763565571f" OR Processes.process_hash="2014d09c7ded74d89c885b5f11693865224116f1b25df9330e61fe528f419d73") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let badHashes = dynamic(["24604384b0e748ada07923630b3d037489e696284a98c4409fb9b6763565571f","2014d09c7ded74d89c885b5f11693865224116f1b25df9330e61fe528f419d73"]);
union
(DeviceFileEvents
| where Timestamp > ago(90d)
| where SHA256 in (badHashes)
| project Timestamp, DeviceName, Kind="FileEvent", ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
(DeviceProcessEvents
| where Timestamp > ago(90d)
| where SHA256 in (badHashes)
| project Timestamp, DeviceName, Kind="ProcessEvent", ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine)
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `216.74.123.126`, `npmjs.store`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `24604384b0e748ada07923630b3d037489e696284a98c4409fb9b6763565571f`, `2014d09c7ded74d89c885b5f11693865224116f1b25df9330e61fe528f419d73`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
