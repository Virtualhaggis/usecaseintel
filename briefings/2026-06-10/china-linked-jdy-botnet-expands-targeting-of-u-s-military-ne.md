# [CRIT] China-linked JDY botnet expands targeting of U.S. military networks

**Source:** BleepingComputer
**Published:** 2026-06-10
**Article:** https://www.bleepingcomputer.com/news/security/china-linked-jdy-botnet-expands-targeting-of-us-military-networks/

## Threat Profile

China-linked JDY botnet expands targeting of U.S. military networks 
By Bill Toulas 
June 10, 2026
11:00 AM
0 


The JDY botnet, a malware network previously associated with Chinese threat actors like Volt Typhoon, has significantly expanded its targeting scope and reconnaissance efforts.


According to researchers at Black Lotus Labs by Lumen, who have been monitoring its activity, JDY maintains a strong focus on the United States, where many of its compromised devices are located and where…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-35616`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1595.001** — Active Scanning: Scanning IP Blocks
- **T1595.002** — Active Scanning: Vulnerability Scanning
- **T1071** — Application Layer Protocol
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1573** — Encrypted Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### JDY botnet fixed source port 19000 TCP SYN scan signature

`UC_3_2` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count as connections, dc(All_Traffic.dest_port) as scanned_ports, dc(All_Traffic.dest) as scanned_hosts, values(All_Traffic.dest_port) as sample_ports from datamodel=Network_Traffic.All_Traffic where All_Traffic.src_port=19000 All_Traffic.transport=tcp by All_Traffic.src, All_Traffic.dest, _time span=5m | `drop_dm_object_name("All_Traffic")` | where scanned_ports > 50 OR scanned_hosts > 25 | sort 0 - _time, - scanned_ports
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where Protocol =~ "Tcp"
| where RemotePort == 19000
| where RemoteIPType == "Public"
| summarize ScannedLocalPorts = dcount(LocalPort), Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleLocalPorts = make_set(LocalPort, 50) by RemoteIP, DeviceId, DeviceName, bin(Timestamp, 5m)
| where ScannedLocalPorts > 25 or Connections > 200
| order by ScannedLocalPorts desc
```

### Internal SOHO/IoT edge device exhibiting outbound mass-scan behaviour (JDY recruitment)

`UC_3_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count as flows, dc(All_Traffic.dest) as distinct_dests, dc(All_Traffic.dest_port) as distinct_ports from datamodel=Network_Traffic.All_Traffic where All_Traffic.transport=tcp by All_Traffic.src, _time span=10m | `drop_dm_object_name("All_Traffic")` | where distinct_dests > 500 AND distinct_ports > 50 | lookup edge_device_inventory.csv src OUTPUT device_type vendor | where isnotnull(device_type) | sort 0 - _time, - distinct_dests
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where Protocol =~ "Tcp"
| where ActionType in ("ConnectionSuccess", "ConnectionFailed", "ConnectionRequest")
| where RemoteIPType == "Public"
| summarize DistinctDestIPs = dcount(RemoteIP), DistinctDestPorts = dcount(RemotePort), TotalFlows = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SamplePorts = make_set(RemotePort, 50) by DeviceId, DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where DistinctDestIPs > 500 and DistinctDestPorts > 50
| order by DistinctDestIPs desc
```

### SOHO/edge/IoT device outbound to Tor entry-node ports (JDY C2 over hidden services)

`UC_3_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count as connections, sum(All_Traffic.bytes_out) as bytes_out, dc(All_Traffic.dest) as distinct_destinations from datamodel=Network_Traffic.All_Traffic where All_Traffic.transport=tcp (All_Traffic.dest_port=9001 OR All_Traffic.dest_port=9030 OR All_Traffic.dest_port=9050 OR All_Traffic.dest_port=9051 OR All_Traffic.dest_port=9150) by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, _time span=1h | `drop_dm_object_name("All_Traffic")` | lookup edge_device_inventory.csv src OUTPUT device_type vendor | where isnotnull(device_type) | sort 0 - connections
```

**Defender KQL:**
```kql
let TorPorts = dynamic([9001, 9030, 9050, 9051, 9150]);
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where Protocol =~ "Tcp"
| where RemotePort in (TorPorts)
| where RemoteIPType == "Public"
| summarize Connections = count(), BytesOut = sum(toint(column_ifexists("AdditionalFields", ""))), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), DistinctDests = dcount(RemoteIP) by DeviceId, DeviceName, InitiatingProcessFileName, RemotePort, bin(Timestamp, 1h)
| where Connections > 5
| order by Connections desc
```

### External scanning of FortiClient EMS targeting CVE-2026-35616 shortly after disclosure

`UC_3_5` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count as attempts, dc(All_Traffic.src) as distinct_sources, values(All_Traffic.src) as sources from datamodel=Network_Traffic.All_Traffic where All_Traffic.transport=tcp (All_Traffic.dest_port=8013 OR All_Traffic.dest_port=8015) by All_Traffic.dest, _time span=1h | `drop_dm_object_name("All_Traffic")` | lookup forticlient_ems_servers.csv dest OUTPUT is_ems_server | where is_ems_server="true" | where distinct_sources > 5 OR attempts > 100 | sort 0 - _time, - distinct_sources
```

**Defender KQL:**
```kql
let EmsPorts = dynamic([8013, 8015]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where Protocol =~ "Tcp"
| where LocalPort in (EmsPorts)
| where RemoteIPType == "Public"
| where ActionType in ("InboundConnectionAccepted", "ConnectionRequest", "ConnectionSuccess")
| summarize Attempts = count(), DistinctSources = dcount(RemoteIP), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleSources = make_set(RemoteIP, 50) by DeviceName, LocalPort, bin(Timestamp, 1h)
| where DistinctSources > 5 or Attempts > 100
| order by DistinctSources desc
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
  - CVE(s): `CVE-2026-35616`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
