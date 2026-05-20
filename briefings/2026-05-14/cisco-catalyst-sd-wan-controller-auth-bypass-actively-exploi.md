# [CRIT] Cisco Catalyst SD-WAN Controller Auth Bypass Actively Exploited to Gain Admin Access

**Source:** The Hacker News, Cisco Talos
**Published:** 2026-05-14
**Article:** https://thehackernews.com/2026/05/cisco-catalyst-sd-wan-controller-auth.html

## Threat Profile

Ongoing exploitation of Cisco Catalyst SD-WAN vulnerabilities 
By 
Cisco Talos 
Thursday, May 14, 2026 12:02
Threat Advisory
Cisco Talos is tracking the active exploitation of CVE-2026-20182 , an authentication bypass vulnerability in Cisco Catalyst SD-WAN Controller, formerly SD-WAN vSmart, and Cisco Catalyst SD-WAN Manager, formerly SD-WAN vManage.
Successful exploitation of CVE-2026-20182 allows an unauthenticated, remote attacker to bypass authentication and obtain administrative privileges …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-20182`
- **CVE:** `CVE-2026-20133`
- **CVE:** `CVE-2026-20128`
- **CVE:** `CVE-2026-20122`
- **CVE:** `CVE-2026-20127`
- **IPv4 (defanged):** `38.181.52.89`
- **IPv4 (defanged):** `89.125.244.33`
- **IPv4 (defanged):** `89.125.244.51`
- **IPv4 (defanged):** `71.80.85.135`
- **IPv4 (defanged):** `212.83.162.37`
- **IPv4 (defanged):** `38.60.214.92`
- **IPv4 (defanged):** `65.20.67.134`
- **IPv4 (defanged):** `104.233.156.1`
- **IPv4 (defanged):** `194.233.100.40`
- **IPv4 (defanged):** `194.163.175.135`
- **IPv4 (defanged):** `23.27.143.170`
- **IPv4 (defanged):** `83.229.126.195`
- **IPv4 (defanged):** `13.62.52.206`
- **IPv4 (defanged):** `79.135.105.208`
- **IPv4 (defanged):** `176.65.139.31`
- **IPv4 (defanged):** `47.104.248.7`
- **Domain (defanged):** `replit.dev`
- **Domain (defanged):** `a820b09-95ba-44eb-b350-417e8241b725-00-1lgwuuen9b77p.worf.replit.dev`
- **SHA256:** `f6f8e0d790645395188fc521039385b7c4f42fa8b426fd035f489f6cda9b5da1`
- **SHA256:** `02654acfb21f83485393ba8b14bd8862b919b9ec966fc6768f6aac1338a45ee8`
- **SHA256:** `0ed72d52347bfe4a78afff8a6982a64050c8fc86d8957a20eeb3e0f3f5342ed0`
- **SHA256:** `96fc528ca5e7d1c2b3add5e31b8797cb126f704976c8fbeaecdbf0aa4309ad46`
- **SHA256:** `7aa88a64a527ade7d93c20faf23b54f2ee33ad9b1246cdc2f8ded2ab639affb1`
- **SHA256:** `0c87871642f84e09e8d3fb23ec36bf55601323e31151a7017a85dbec929cf15d`
- **SHA256:** `18d77c9c5bbb5b9d5bdfd366fdfcf26bad9e64c63ca865fad711bcce8e3d5a80`
- **SHA256:** `d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa`
- **SHA256:** `5bc5998161056b7c8f70c9724d8a63abc7ff8c3843b91c30cffab0899e39b7f8`
- **SHA256:** `b0f51b098842cd630097b462aab0ec357e2c7824af37cca6d08165265da2c2d3`
- **SHA256:** `72f570ce97de3eaaffef33d90b0c337a153fc9690cc34ee207b557d868360060`
- **SHA256:** `17302d903baf182f94dc3be40ab1e0874dd0eb2ec5255bf9131fd53591efe925`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1505.003** — Server Software Component: Web Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.002** — Encrypted Channel: Asymmetric Cryptography
- **T1496** — Resource Hijacking
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound exploit traffic to Cisco SD-WAN from UAT-8616 / Cluster IPs (CVE-2026-20182, -20133/-20128/-20122)

`UC_80_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.dest_ip) as dest_ips from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_ip IN ("38.181.52.89","89.125.244.33","89.125.244.51","71.80.85.135","212.83.162.37","38.60.214.92","65.20.67.134","104.233.156.1","194.233.100.40","194.163.175.135","23.27.143.170") AND All_Traffic.dest_port IN (443,8443,830,22,4445,7443,31337) by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("38.181.52.89","89.125.244.33","89.125.244.51","71.80.85.135","212.83.162.37","38.60.214.92","65.20.67.134","104.233.156.1","194.233.100.40","194.163.175.135","23.27.143.170")
     or LocalIP in ("38.181.52.89","89.125.244.33","89.125.244.51","71.80.85.135","212.83.162.37","38.60.214.92","65.20.67.134","104.233.156.1","194.233.100.40","194.163.175.135","23.27.143.170")
| where RemotePort in (443, 8443, 830, 22, 4445, 7443, 31337)
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] JSP webshell deployment on Cisco SD-WAN Manager (XenShell / Godzilla / Behinder)

`UC_80_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.dest) as dest from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_name IN ("sysv.jsp","sysinit.jsp","conf.jsp","20251117022131.jsp","vmurnp_ikp.jsp") OR Filesystem.file_path="*.jsp" AND Filesystem.file_path="*webapps*") by Filesystem.file_name Filesystem.file_path Filesystem.dest | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FileName in~ ("sysv.jsp","sysinit.jsp","conf.jsp","20251117022131.jsp","vmurnp_ikp.jsp")
   or (FolderPath has_any ("/opt/web-app/","/var/lib/tomcat","/webapps/","vmanage") and FileName endswith ".jsp")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Cisco SD-WAN post-exploit C2 callback: AdaptixC2 / Sliver / Mythic on Clusters 5

`UC_80_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.bytes_out) as bytes_out values(All_Traffic.src) as src from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("194.163.175.135","23.27.143.170") AND All_Traffic.dest_port IN (4445,7443,31337,443,22) by All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.src_ip All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteIP in ("194.163.175.135","23.27.143.170")
| where RemotePort in (4445, 7443, 31337, 443, 22)
| summarize ConnectionCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), BytesSent = sum(tolong(extractjson("$.bytes_sent", AdditionalFields))), Processes = make_set(InitiatingProcessFileName) by DeviceName, RemoteIP, RemotePort
| order by FirstSeen desc
```

### [LLM] XMRig cryptominer deployment on exploited Cisco SD-WAN (Cluster 7)

`UC_80_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent from datamodel=Endpoint.Processes where (Processes.process="*xmrig*" OR Processes.process="*--donate-level*" OR Processes.process="*pool.minexmr*" OR Processes.process="*stratum+tcp*" OR Processes.process="*config.json*xmrig*" OR (Processes.process_name IN ("curl","wget") AND Processes.process="*83.229.*")) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where (ProcessCommandLine has_any ("xmrig","--donate-level","stratum+tcp://","--cpu-priority","pool.minexmr","randomx")
   or (InitiatingProcessFileName in~ ("curl","wget","bash","sh") and ProcessCommandLine has "83.229.")
   or (FileName in~ ("curl","wget") and ProcessCommandLine has_any ("xmrig","config.json") and ProcessCommandLine has "83.229."))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### [LLM] Known-bad SHA256 execution on Cisco SD-WAN — UAT-8616 / Cluster IOC sample match

`UC_80_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("f6f8e0d790645395188fc521039385b7c4f42fa8b426fd035f489f6cda9b5da1","02654acfb21f83485393ba8b14bd8862b919b9ec966fc6768f6aac1338a45ee8","0ed72d52347bfe4a78afff8a6982a64050c8fc86d8957a20eeb3e0f3f5342ed0","96fc528ca5e7d1c2b3add5e31b8797cb126f704976c8fbeaecdbf0aa4309ad46","7aa88a64a527ade7d93c20faf23b54f2ee33ad9b1246cdc2f8ded2ab639affb1","0c87871642f84e09e8d3fb23ec36bf55601323e31151a7017a85dbec929cf15d","18d77c9c5bbb5b9d5bdfd366fdfcf26bad9e64c63ca865fad711bcce8e3d5a80","d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let TalosIOCs = dynamic(["f6f8e0d790645395188fc521039385b7c4f42fa8b426fd035f489f6cda9b5da1","02654acfb21f83485393ba8b14bd8862b919b9ec966fc6768f6aac1338a45ee8","0ed72d52347bfe4a78afff8a6982a64050c8fc86d8957a20eeb3e0f3f5342ed0","96fc528ca5e7d1c2b3add5e31b8797cb126f704976c8fbeaecdbf0aa4309ad46","7aa88a64a527ade7d93c20faf23b54f2ee33ad9b1246cdc2f8ded2ab639affb1","0c87871642f84e09e8d3fb23ec36bf55601323e31151a7017a85dbec929cf15d","18d77c9c5bbb5b9d5bdfd366fdfcf26bad9e64c63ca865fad711bcce8e3d5a80","d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa"]);
union isfuzzy=true
  (DeviceFileEvents | where Timestamp > ago(90d) | where SHA256 in (TalosIOCs) | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceProcessEvents | where Timestamp > ago(90d) | where SHA256 in (TalosIOCs) | project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceEvents | where Timestamp > ago(90d) | where SHA256 in (TalosIOCs) | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine)
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

### Article-specific behavioural hunt — Cisco Catalyst SD-WAN Controller Auth Bypass Actively Exploited to Gain Admin Ac

`UC_80_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Cisco Catalyst SD-WAN Controller Auth Bypass Actively Exploited to Gain Admin Ac ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("miner.sh","loot_run.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/moneroocean/miner.sh*" OR Filesystem.file_path="*/tmp/moneroocean/config_background.json*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("miner.sh","loot_run.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Cisco Catalyst SD-WAN Controller Auth Bypass Actively Exploited to Gain Admin Ac
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("miner.sh", "loot_run.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/moneroocean/miner.sh", "/tmp/moneroocean/config_background.json", "/dev/null") or FileName in~ ("miner.sh", "loot_run.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `38.181.52.89`, `89.125.244.33`, `89.125.244.51`, `71.80.85.135`, `212.83.162.37`, `38.60.214.92`, `65.20.67.134`, `104.233.156.1` _(+10 more)_

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-20182`, `CVE-2026-20133`, `CVE-2026-20128`, `CVE-2026-20122`, `CVE-2026-20127`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `f6f8e0d790645395188fc521039385b7c4f42fa8b426fd035f489f6cda9b5da1`, `02654acfb21f83485393ba8b14bd8862b919b9ec966fc6768f6aac1338a45ee8`, `0ed72d52347bfe4a78afff8a6982a64050c8fc86d8957a20eeb3e0f3f5342ed0`, `96fc528ca5e7d1c2b3add5e31b8797cb126f704976c8fbeaecdbf0aa4309ad46`, `7aa88a64a527ade7d93c20faf23b54f2ee33ad9b1246cdc2f8ded2ab639affb1`, `0c87871642f84e09e8d3fb23ec36bf55601323e31151a7017a85dbec929cf15d`, `18d77c9c5bbb5b9d5bdfd366fdfcf26bad9e64c63ca865fad711bcce8e3d5a80`, `d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa` _(+4 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
