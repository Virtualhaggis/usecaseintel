# [LOW] SHEETCREEP C# RAT Abuses Google Sheets API as C2 to Target Diplomatic Organizations

**Source:** Cyber Security News
**Published:** 2026-06-12
**Article:** https://cybersecuritynews.com/sheetcreep-c-rat-abuses-google-sheets-api/

## Threat Profile

A newly identified remote access trojan named SHEETCREEP is making headlines for its clever use of Google Sheets as a hidden communication channel between attackers and infected machines. This C# malware targets diplomatic organizations, using a carefully crafted lure to trick victims into executing it on their systems. The campaign represents a calculated move by [&#8230;] The post SHEETCREEP C# RAT Abuses Google Sheets API as C2 to Target Diplomatic Organizations appeared first on Cyber Securi…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `1ba67bb1cfad42446880cca53cbd05fe66d7514b2bb139b48e5c63adff14be7b`
- **SHA256:** `2cc7c2d8653c98e5bac32fcaf5e45b861efb4bb87df3b3f96285edb475e75bba`
- **SHA256:** `62d62950ff7a0e43550a5d0ba55d32d5083b9de5538e0f012e406b6d951e16aa`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1ba67bb1cfad42446880cca53cbd05fe66d7514b2bb139b48e5c63adff14be7b`, `2cc7c2d8653c98e5bac32fcaf5e45b861efb4bb87df3b3f96285edb475e75bba`, `62d62950ff7a0e43550a5d0ba55d32d5083b9de5538e0f012e406b6d951e16aa`


## Why this matters

Severity classified as **LOW** based on: IOCs present, 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
