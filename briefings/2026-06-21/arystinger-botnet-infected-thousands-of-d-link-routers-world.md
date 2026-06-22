# [HIGH] AryStinger botnet infected thousands of D-Link routers worldwide

**Source:** BleepingComputer
**Published:** 2026-06-21
**Article:** https://www.bleepingcomputer.com/news/security/arystinger-botnet-infected-thousands-of-d-link-routers-worldwide/

## Threat Profile

AryStinger botnet infected thousands of D-Link routers worldwide 
By Bill Toulas 
June 21, 2026
10:14 AM
0 
A previously undocumented malware botnet named AryStinger has compromised more than 4,000 outdated routers to turn them into proxies for malicious traffic.
Researchers at Qianxin's XLab threat intelligence team say that the malware converts infected devices into remotely controlled “executors” that can perform scanning, proxying, tunneling, command execution, and other activities on behalf…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2013-3307`
- **CVE:** `CVE-2016-5681`
- **CVE:** `CVE-2025-11837`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1090** — Proxy
- **T1133** — External Remote Services
- **T1572** — Protocol Tunneling
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1505** — Server Software Component

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AryStinger C2 beaconing to ajb8/ahb8/auq8/dataexplore/ary2 infrastructure

`UC_15_2` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*ajb8.com" OR DNS.query="*ahb8.com" OR DNS.query="*auq8.com" OR DNS.query="*dataexplore.cc" OR DNS.query="*dataexplore.co" OR DNS.query="*ary2.com" OR DNS.query="*opi7.com") by DNS.src DNS.dest DNS.query | `drop_dm_object_name("DNS")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let c2Tokens = dynamic(["ajb8","ahb8","auq8","dataexplore","ary2","opi7"]);
let c2IP = "107.150.106.14";
union
 (DeviceNetworkEvents
  | where Timestamp > ago(14d)
  | where RemoteIP == c2IP or RemoteUrl has_any (c2Tokens)
  | project Timestamp, DeviceName, Source="Network", RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine),
 (DeviceEvents
  | where Timestamp > ago(14d)
  | where ActionType == "DnsQueryResponse"
  | where RemoteUrl has_any (c2Tokens)
  | project Timestamp, DeviceName, Source="DNS", RemoteIP, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine)
| order by Timestamp desc
```

### Inbound CVE-2016-5681 exploitation of D-Link DIR-850L /dws/api/Login (port 8181)

`UC_15_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*/dws/api/Login*" Web.http_method=POST (Web.dest_port=8181 OR Web.url="*8181*") by Web.src Web.dest Web.dest_port Web.url Web.http_user_agent | `drop_dm_object_name("Web")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where ActionType in ("InboundConnectionAccepted","ConnectionRequest","ListeningConnectionCreated")
| where LocalPort == 8181
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, LocalIP, LocalPort, ActionType, InitiatingProcessFileName
| order by Timestamp desc
```

### AryStinger executor tooling: gs-netcat/dropbear tunnels and known payload hashes on NAS

`UC_15_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="gs-netcat" OR (Processes.process_name="dropbear" AND (Processes.process_path="*/tmp/*" OR Processes.process_path="*/dev/shm/*" OR Processes.process_path="*/var/tmp/*"))) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name("Processes")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let badHashes = dynamic(["df0c9f6289e56f31c0700f40590857d3","98e55d712a99d2cd45e8592c6dda5110","10ba24db187836efe77ed7e75d279d33","6f761f63642cd6329a29cfad80be50c3","dbcc5a3e6afe41060d6357e24dc03fd3","a97e552f5e655e1cfa56853f65beeb0e","c113739225ece5f6e4805466dec1401d","0a2d2a4ec1aa2aa6a23a35abb5a75451","dd1e5a3cd9f842bd70be45a62c3ebbf6","6f91d1f8f0cbaab137351936b52f7a94","7b361a6d0d42309d09ec9000b53712b3","18f894a3168ee0b809eed321a2e748b4","b9406e969cdfdaef433e93d0b9ad1f5d","f093891e281bcd9c8016dea7d89cc671","9221423d7daff9e64f7e2af54f911fea","7f2b2e3516fa454adfd51f857ae80adf","d79270ba44e665ebb0383eb77a52e38b","36ff9f683f870145aaf5a715bc934762","dc35086ba0f5f83545c32a023a1f3be4","7461445fca3f9d8911148e0908d33c3b"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FileName =~ "gs-netcat")
     or (FileName =~ "dropbear" and FolderPath has_any ("/tmp/","/var/tmp/","/dev/shm/","/mnt/","/var/run/"))
     or (MD5 in~ (badHashes))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, MD5, SHA256
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2013-3307`, `CVE-2016-5681`, `CVE-2025-11837`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
