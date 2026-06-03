# [MED] HazyBeacon Camapign Weaponizes Amazon Web Services for Stealthy Communications

**Source:** Cyber Security News
**Published:** 2026-06-03
**Article:** https://cybersecuritynews.com/hazybeacon-camapign-weaponizes-amazon-web-services/

## Threat Profile

A new malware campaign is turning trusted cloud infrastructure against the organizations that rely on it. Known as HazyBeacon and tracked under cluster identifier CL-STA-1020, the campaign targets government networks across Southeast Asia. Rather than using easily blocked servers, the threat actors hide inside one of the world&#8217;s most trusted platforms, Amazon Web Services (AWS). [&#8230;] The post HazyBeacon Camapign Weaponizes Amazon Web Services for Stealthy Communications appeared first…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `lambda-url.ap-southeast-1.on.aws`
- **SHA256:** `4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30`
- **SHA256:** `d20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa`
- **SHA256:** `304c615f4a8c2c2b36478b693db767d41be998032252c8159cc22c18a65ab498`
- **SHA256:** `f0c9481513156b0cdd216d6dfb53772839438a2215d9c5b895445f418b64b886`
- **SHA256:** `3255798db8936b5b3ae9fed6292413ce20da48131b27394c844ecec186a1e92f`
- **SHA256:** `279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e`
- **SHA256:** `d961aca6c2899cc1495c0e64a29b85aa226f40cf9d42dadc291c4f601d6e27c3`

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
  - IP / domain IOC(s): `lambda-url.ap-southeast-1.on.aws`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `4931df8650521cfd686782919bda0f376475f9fc5f1fee9d7cf3a4e0d9c73e30`, `d20b536c88ecd326f79d7a9180f41a2e47a40fcf2cc6a2b02d68a081c89eaeaa`, `304c615f4a8c2c2b36478b693db767d41be998032252c8159cc22c18a65ab498`, `f0c9481513156b0cdd216d6dfb53772839438a2215d9c5b895445f418b64b886`, `3255798db8936b5b3ae9fed6292413ce20da48131b27394c844ecec186a1e92f`, `279e60e77207444c7ec7421e811048267971b0db42f4b4d3e975c7d0af7f511e`, `d961aca6c2899cc1495c0e64a29b85aa226f40cf9d42dadc291c4f601d6e27c3`


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
