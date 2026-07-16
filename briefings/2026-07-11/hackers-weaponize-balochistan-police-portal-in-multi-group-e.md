# [HIGH] Hackers Weaponize Balochistan Police Portal in Multi-Group Espionage Campaigns

**Source:** The Hacker News
**Published:** 2026-07-11
**Article:** https://thehackernews.com/2026/07/hackers-weaponize-balochistan-police.html

## Threat Profile

Hackers Weaponize Balochistan Police Portal in Multi-Group Espionage Campaigns 
 Ravie Lakshmanan  Jul 11, 2026 Threat Intelligence / Cyber Espionage 
Cybersecurity researchers have disclosed details of sustained cyber espionage activity against several Pakistani law enforcement organizations undertaken by suspected China- and India-aligned threat actors between February 2024 and April 2026.
"At Balochistan Police, the compromised assets included servers hosting web applications that manage po…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `142.171.183.8`
- **IPv4 (defanged):** `193.42.25.65`
- **IPv4 (defanged):** `41.216.188.140`
- **IPv4 (defanged):** `89.31.121.220`
- **IPv4 (defanged):** `45.125.32.218`
- **IPv4 (defanged):** `172.111.233.36`
- **IPv4 (defanged):** `172.111.233.96`
- **IPv4 (defanged):** `172.111.233.12`
- **IPv4 (defanged):** `172.111.233.105`
- **IPv4 (defanged):** `172.111.233.26`
- **IPv4 (defanged):** `172.94.9.49`
- **IPv4 (defanged):** `172.94.9.43`
- **IPv4 (defanged):** `172.94.9.19`
- **IPv4 (defanged):** `45.74.6.17`
- **Domain (defanged):** `cms.balochistanpolice.gov.pk`
- **SHA1:** `23f6781919a50b118d8d4e6a7e9ae63b71ecc885`
- **SHA1:** `4039454c9189e64285e93fc075a30b93f814b5b5`
- **SHA1:** `58cb2d95063b9df807b7aa8dc106b74ce988a491`
- **SHA1:** `000fad96a85dd6933c22d3dbec9aed47b7f1f066`
- **SHA1:** `08570471f39bb6725f07b8cddbea99ed48c22686`
- **SHA1:** `23f4766c011d193f076dfc735dc460e2a41ead79`
- **SHA1:** `47f8cb0c2dcf62702f58cfc1603d6325755f6820`
- **SHA1:** `5d60ff36ff519c2e13e7f66cfa0bb46be79592a7`
- **SHA1:** `63b88d00331de88af696dfb7a896935d830e485f`
- **SHA1:** `8c329db96e093fa25268e078405a33c518dbb5c9`
- **SHA1:** `d66ab0cd2e44dc8389c111b7ea34c7bcb0b35311`
- **SHA1:** `2bab40c55637398f0497cff9c8cbea564d595c7f`
- **SHA1:** `539bd79fbb684edea94eb37518134b97e94b9dd8`
- **SHA1:** `6fe2e74d009abbd56de01fd7404a1245e9b47c79`
- **SHA1:** `71757adba833b46f961e840d0f055bcce0b529c4`
- **SHA1:** `c6c197e61079a0a33108c2c87b5e3c7056a138ec`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1620** — Reflective Code Loading
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### cms_plugin.exe Rust stager execution + payload pull from 193.42.25.65

`UC_103_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="cms_plugin.exe" OR Processes.original_file_name="cms_plugin.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "193.42.25.65" or InitiatingProcessFileName =~ "cms_plugin.exe"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### Fake 360Safe.exe (.NET) reflectively loading AsyncRAT

`UC_103_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="360Safe.exe" NOT (Processes.process_path="C:\\Program Files (x86)\\360\\*" OR Processes.process_path="C:\\Program Files\\360\\*") by Processes.dest Processes.user Processes.process Processes.parent_process_name Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "360Safe.exe"
| where not(ProcessVersionInfoCompanyName has_any ("360","Qihoo")) or FolderPath !startswith "C:\\Program Files"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessCommandLine, SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

### Beaconing to Balochistan Police espionage C2 / stager IP set

`UC_103_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("142.171.183.8","193.42.25.65","41.216.188.140","89.31.121.220","45.125.32.218","172.111.233.36","172.111.233.96","172.111.233.12","172.111.233.105","172.111.233.26","172.94.9.49","172.94.9.43","172.94.9.19","45.74.6.17") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("142.171.183.8","193.42.25.65","41.216.188.140","89.31.121.220","45.125.32.218","172.111.233.36","172.111.233.96","172.111.233.12","172.111.233.105","172.111.233.26","172.94.9.49","172.94.9.43","172.94.9.19","45.74.6.17")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Conns=count(), Ports=make_set(RemotePort,10) by DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath
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

### Article-specific behavioural hunt — Hackers Weaponize Balochistan Police Portal in Multi-Group Espionage Campaigns

`UC_103_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Weaponize Balochistan Police Portal in Multi-Group Espionage Campaigns ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("cms_plugin.exe","360safe.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("cms_plugin.exe","360safe.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Weaponize Balochistan Police Portal in Multi-Group Espionage Campaigns
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("cms_plugin.exe", "360safe.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("cms_plugin.exe", "360safe.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `142.171.183.8`, `193.42.25.65`, `41.216.188.140`, `89.31.121.220`, `45.125.32.218`, `172.111.233.36`, `172.111.233.96`, `172.111.233.12` _(+7 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `23f6781919a50b118d8d4e6a7e9ae63b71ecc885`, `4039454c9189e64285e93fc075a30b93f814b5b5`, `58cb2d95063b9df807b7aa8dc106b74ce988a491`, `000fad96a85dd6933c22d3dbec9aed47b7f1f066`, `08570471f39bb6725f07b8cddbea99ed48c22686`, `23f4766c011d193f076dfc735dc460e2a41ead79`, `47f8cb0c2dcf62702f58cfc1603d6325755f6820`, `5d60ff36ff519c2e13e7f66cfa0bb46be79592a7` _(+8 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
