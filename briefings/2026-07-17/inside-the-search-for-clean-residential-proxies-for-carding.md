# [MED] Inside the Search for "Clean" Residential Proxies for Carding

**Source:** BleepingComputer
**Published:** 2026-07-17
**Article:** https://www.bleepingcomputer.com/news/security/inside-the-search-for-clean-residential-proxies-for-carding/

## Threat Profile

Inside the Search for "Clean" Residential Proxies for Carding 
Sponsored by Flare 
July 17, 2026
10:00 AM
0 
Residential proxies are no longer treated as a simple anonymity tool in carding circles. They are increasingly discussed as one component of a broader identity-simulation stack, alongside device fingerprints, browser profiles, billing information, time zones, cookies, and transaction behavior.
To better understand how criminal actors currently use and evaluate this infrastructure, Flare r…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `netnut.com`
- **Domain (defanged):** `netnut.io`
- **Domain (defanged):** `alarum.io`
- **Domain (defanged):** `ascarding.net`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.002** — Proxy: External Proxy
- **T1090.003** — Proxy: Multi-hop Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Corporate endpoint browsing the ascarding.net carding forum

`UC_10_1` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_host="*ascarding.net*" OR All_Traffic.url="*ascarding.net*" by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.user All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "ascarding.net"
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Urls=make_set(RemoteUrl,10) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP
| order by FirstSeen desc
```

### Internal host connecting to NetNut / Alarum residential-proxy infrastructure

`UC_10_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host IN ("*netnut.com","*netnut.io","*alarum.io") OR All_Traffic.url IN ("*netnut.com*","*netnut.io*","*alarum.io*")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.user All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("netnut.com","netnut.io","alarum.io")
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Urls=make_set(RemoteUrl,10) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by FirstSeen desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `netnut.com`, `netnut.io`, `alarum.io`, `ascarding.net`


## Why this matters

Severity classified as **MED** based on: IOCs present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
