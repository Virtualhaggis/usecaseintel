# [HIGH] NetNut proxy network disrupted, 2 million infected devices cut off

**Source:** BleepingComputer
**Published:** 2026-07-03
**Article:** https://www.bleepingcomputer.com/news/security/netnut-proxy-network-disrupted-2-million-infected-devices-cut-off/

## Threat Profile

NetNut proxy network disrupted, 2 million infected devices cut off 
By Ionut Ilascu 
July 3, 2026
01:50 PM
1 
A joint operation involving Google has disrupted NetNut, a residential proxy network that gave access to millions of compromised Android devices, including smart TVs and streaming boxes.
Also known as Popa, the NetNut botnet allowed cybercriminals and espionage groups to hide behind legitimate home internet addresses when launching attacks.
According to the Google Threat Intelligence Gro…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `netnut.com`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1090.002** — Proxy: External Proxy
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Enterprise host egress to seized NetNut/Popa residential-proxy infrastructure (netnut.io, proxyjet.io, divinetworks.com)

`UC_41_2` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*netnut.io" OR DNS.query="*netnut.com" OR DNS.query="*proxyjet.io" OR DNS.query="*divinetworks.com") by DNS.src DNS.dest DNS.query | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let ProxyDomains = dynamic(["netnut.io","netnut.com","proxyjet.io","divinetworks.com"]);
union
(DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (ProxyDomains)
  | project Timestamp, DeviceName, Source="NetworkConnect", InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort),
(DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | where RemoteUrl has_any (ProxyDomains)
  | project Timestamp, DeviceName, Source="DnsQuery", InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP=column_ifexists("RemoteIP",""), RemotePort=column_ifexists("RemotePort",0))
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

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `netnut.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
