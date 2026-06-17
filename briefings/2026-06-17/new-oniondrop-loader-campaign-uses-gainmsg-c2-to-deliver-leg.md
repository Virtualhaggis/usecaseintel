# [MED] New OnionDrop Loader Campaign Uses gainmsg C2 to Deliver LegionLoader Payloads

**Source:** Cyber Security News
**Published:** 2026-06-17
**Article:** https://cybersecuritynews.com/new-oniondrop-loader-campaign-uses-gainmsg-c2/

## Threat Profile

A newly identified loader campaign is raising serious concerns across the cybersecurity community. Threat researchers have uncovered an active operation using a sophisticated multi-stage loader called OnionDrop, which is being used to deliver harmful payloads, including the well-known LegionLoader, to a broad range of victims at scale. OnionDrop has been quietly operating since at least [&#8230;] The post New OnionDrop Loader Campaign Uses gainmsg C2 to Deliver LegionLoader Payloads appeared fir…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `gainmsg.com`
- **SHA256:** `8559e535128805f1e31fa7a15b33d25ae498915c7b88ea5142cf38858d551a53`
- **SHA256:** `f09be48aab38dc85b7ad46efb98897617af66014ded44a7cf1bddaab59d9dad2`
- **SHA256:** `18bb95789e8727be0d98d9a5fce027f0f514e74192c7736b3afa297d2ee4a8fb`
- **SHA256:** `070a97bf5bcba13c41266a79357e2a5b8d6f4e353db7427bd8ccabceee5c96e3`
- **SHA256:** `892f1bd9663c7e14855a0238e0fbb5b2396000b3396ceda79947374a3da78912`
- **SHA256:** `c9b96846c9a49ddbed9e143b098972e1d7880654f763bb504d2f7b5d2ab1dafb`
- **SHA256:** `fb31df58549031f0ea24b250b214cbab9eafa39adaa715c675f328f7370904c7`
- **SHA256:** `f6e5f7445b9ea717513a04d04acfa343025ca35302d025de33935e176a83f6ae`
- **SHA256:** `0a8914b4f794ebc8ea1ce08dd4b5da918cd9697443007622100b0ba0731d428c`

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
  - IP / domain IOC(s): `gainmsg.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `8559e535128805f1e31fa7a15b33d25ae498915c7b88ea5142cf38858d551a53`, `f09be48aab38dc85b7ad46efb98897617af66014ded44a7cf1bddaab59d9dad2`, `18bb95789e8727be0d98d9a5fce027f0f514e74192c7736b3afa297d2ee4a8fb`, `070a97bf5bcba13c41266a79357e2a5b8d6f4e353db7427bd8ccabceee5c96e3`, `892f1bd9663c7e14855a0238e0fbb5b2396000b3396ceda79947374a3da78912`, `c9b96846c9a49ddbed9e143b098972e1d7880654f763bb504d2f7b5d2ab1dafb`, `fb31df58549031f0ea24b250b214cbab9eafa39adaa715c675f328f7370904c7`, `f6e5f7445b9ea717513a04d04acfa343025ca35302d025de33935e176a83f6ae` _(+1 more)_


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
