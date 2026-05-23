# [MED] US and Canada arrest and charge suspected Kimwolf botnet admin

**Source:** BleepingComputer
**Published:** 2026-05-22
**Article:** https://www.bleepingcomputer.com/news/security/us-and-canada-arrest-and-charge-suspected-kimwolf-botnet-admin/

## Threat Profile

US and Canada arrest and charge suspected Kimwolf botnet admin 
By Sergiu Gatlan 
May 22, 2026
05:01 AM
0 
U.S. and Canadian authorities arrested and charged a Canadian man with operating the KimWolf distributed denial-of-service (DDoS) botnet, which infected nearly two million devices worldwide.
23-year-old Jacob Butler (also known online as "Dort") was arrested by Canadian authorities in Ottawa on Wednesday pursuant to an extradition warrant.
According to a criminal complaint unsealed on Thurs…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `64.188.68.193`
- **IPv4 (defanged):** `194.46.59.169`
- **IPv4 (defanged):** `104.171.170.241`
- **IPv4 (defanged):** `104.171.170.253`
- **IPv4 (defanged):** `107.173.196.189`
- **IPv4 (defanged):** `78.108.178.100`
- **Domain (defanged):** `ilovegaysex.su`
- **Domain (defanged):** `coerece.ilovegaysex.su`
- **Domain (defanged):** `approach.ilovegaysex.su`
- **Domain (defanged):** `updatetoto.tw`
- **SHA1:** `09894c3414b42addbf12527b0842ee7011e70cfd`
- **SHA1:** `51d9a914b8d35bb26d37ff406a712f41d2075bc6`
- **SHA1:** `616a3bef8b0be85a3c2bc01bbb5fb4a5f98bf707`
- **SHA1:** `ccf40dfe7ae44d5e6922a22beed710f9a1812725`
- **SHA1:** `26e9e38ec51d5a31a892e57908cb9727ab60cf88`
- **SHA1:** `08e9620a1b36678fe8406d1a231a436a752f5a5e`
- **SHA1:** `053a0abe0600d16a91b822eb538987bca3f3ab55`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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
  - IP / domain IOC(s): `64.188.68.193`, `194.46.59.169`, `104.171.170.241`, `104.171.170.253`, `107.173.196.189`, `78.108.178.100`, `ilovegaysex.su`, `coerece.ilovegaysex.su` _(+2 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `09894c3414b42addbf12527b0842ee7011e70cfd`, `51d9a914b8d35bb26d37ff406a712f41d2075bc6`, `616a3bef8b0be85a3c2bc01bbb5fb4a5f98bf707`, `ccf40dfe7ae44d5e6922a22beed710f9a1812725`, `26e9e38ec51d5a31a892e57908cb9727ab60cf88`, `08e9620a1b36678fe8406d1a231a436a752f5a5e`, `053a0abe0600d16a91b822eb538987bca3f3ab55`


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
