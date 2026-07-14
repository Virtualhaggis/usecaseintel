# [CRIT] One Target, Two Flags | Rival Espionage Actors Converge On Pakistani Law Enforcement

**Source:** SentinelLabs
**Published:** 2026-07-09
**Article:** https://www.sentinelone.com/labs/one-target-china-india-espionage-converge-on-pakistani-law-enforcement/

## Threat Profile

Adversary 
One Target, Two Flags | Rival Espionage Actors Converge On Pakistani Law Enforcement 
Aleksandar Milenkoski & Julian-Ferdinand Vögele 
/
July 9, 2026 
Executive Summary 
SentinelLABS has been tracking sustained cyberespionage activity against several Pakistani law enforcement organizations, taking place from February 2024 to April 2026.
All these actors converged on Balochistan Police over this period, bringing both a partner and an adversary of Pakistan to the same police force in a …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `172.111.233.36`
- **IPv4 (defanged):** `172.111.233.96`
- **IPv4 (defanged):** `172.111.233.12`
- **IPv4 (defanged):** `172.111.233.105`
- **IPv4 (defanged):** `172.111.233.26`
- **IPv4 (defanged):** `172.94.9.49`
- **IPv4 (defanged):** `172.94.9.43`
- **IPv4 (defanged):** `172.94.9.19`
- **IPv4 (defanged):** `45.74.6.17`
- **IPv4 (defanged):** `45.125.32.218`
- **IPv4 (defanged):** `142.171.183.8`
- **IPv4 (defanged):** `193.42.25.65`
- **IPv4 (defanged):** `89.31.121.220`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573** — Encrypted Channel
- **T1219** — Remote Access Software
- **T1505.003** — Server Software Component: Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Outbound C2 to PlugX/ShadowPad/Cobalt Strike/Remcos infrastructure targeting Pakistani law enforcement

`UC_86_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("172.111.233.36","172.111.233.96","172.111.233.12","172.111.233.105","172.111.233.26","172.94.9.49","172.94.9.43","172.94.9.19","45.74.6.17","45.125.32.218","142.171.183.8","193.42.25.65","89.31.121.220") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.transport | `drop_dm_object_name("All_Traffic")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let C2 = dynamic(["172.111.233.36","172.111.233.96","172.111.233.12","172.111.233.105","172.111.233.26","172.94.9.49","172.94.9.43","172.94.9.19","45.74.6.17","45.125.32.218","142.171.183.8","193.42.25.65","89.31.121.220"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (C2)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ConnCount=count(), Ports=make_set(RemotePort, 20) by DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by LastSeen desc
```

### Compromised web-application server beaconing to espionage C2 (portal-update implant)

`UC_86_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true allow_old_summaries=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("172.111.233.36","172.111.233.96","172.111.233.12","172.111.233.105","172.111.233.26","172.94.9.49","172.94.9.43","172.94.9.19","45.74.6.17","45.125.32.218","142.171.183.8","193.42.25.65","89.31.121.220") AND (All_Traffic.process="*\\w3wp.exe" OR All_Traffic.process="*\\java.exe" OR All_Traffic.process="*\\httpd.exe" OR All_Traffic.process="*\\nginx.exe" OR All_Traffic.process="*\\php-cgi.exe" OR All_Traffic.process="*\\tomcat*.exe") by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process | `drop_dm_object_name("All_Traffic")` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let C2 = dynamic(["172.111.233.36","172.111.233.96","172.111.233.12","172.111.233.105","172.111.233.26","172.94.9.49","172.94.9.43","172.94.9.19","45.74.6.17","45.125.32.218","142.171.183.8","193.42.25.65","89.31.121.220"]);
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP in (C2)
| where InitiatingProcessFileName in~ ("w3wp.exe","java.exe","httpd.exe","nginx.exe","php-cgi.exe","tomcat.exe","javaw.exe","node.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName
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

### Article-specific behavioural hunt — One Target, Two Flags | Rival Espionage Actors Converge On Pakistani Law Enforce

`UC_86_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — One Target, Two Flags | Rival Espionage Actors Converge On Pakistani Law Enforce ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("cms_plugin.exe","360safe.exe") OR Processes.process_path="*D:\codedome\case\six\Client\Client2\obj\Debug\Client2.pdb*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*D:\codedome\case\six\Client\Client2\obj\Debug\Client2.pdb*" OR Filesystem.file_name IN ("cms_plugin.exe","360safe.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — One Target, Two Flags | Rival Espionage Actors Converge On Pakistani Law Enforce
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("cms_plugin.exe", "360safe.exe") or FolderPath has_any ("D:\codedome\case\six\Client\Client2\obj\Debug\Client2.pdb"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("D:\codedome\case\six\Client\Client2\obj\Debug\Client2.pdb") or FileName in~ ("cms_plugin.exe", "360safe.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `172.111.233.36`, `172.111.233.96`, `172.111.233.12`, `172.111.233.105`, `172.111.233.26`, `172.94.9.49`, `172.94.9.43`, `172.94.9.19` _(+5 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 5 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
