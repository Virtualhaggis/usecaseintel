# [HIGH] Netherlands seizes 800 servers of hosting firm enabling cyberattacks

**Source:** BleepingComputer
**Published:** 2026-05-22
**Article:** https://www.bleepingcomputer.com/news/security/netherlands-seizes-800-servers-of-hosting-firm-enabling-cyberattacks/

## Threat Profile

Netherlands seizes 800 servers of hosting firm enabling cyberattacks 
By Bill Toulas 
May 22, 2026
01:24 PM
0 
Financial crime investigators in the Netherlands (FIOD) arrested two men and seized 800 servers linked to a web hosting company that enabled cyberattacks, interference operations, and disinformation campaigns.
FIOD arrested a 57-year-old suspect, who was the company director, and a 39-year-old who headed a separate firm that provided internet connectivity.
According to the authorities, …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `stark-industries.solutions`
- **Domain (defanged):** `the.hosting`
- **Domain (defanged):** `worktitans.nl`
- **Domain (defanged):** `pq.hosting`
- **Domain (defanged):** `ufo.hosting`
- **Domain (defanged):** `bill-migration-db.stark-industries.solutions`
- **Domain (defanged):** `pq-ru.digitalvpn.org`
- **Domain (defanged):** `pq.company`
- **Domain (defanged):** `registry.pq.hosting`
- **Domain (defanged):** `russia.stark-industries.solutions`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1583.003** — Acquire Infrastructure: Virtual Private Server
- **T1090.003** — Proxy: Multi-hop Proxy
- **T1498.001** — Network Denial of Service: Direct Network Flood

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound traffic to sanctioned Stark Industries / WorkTitans / PQ-Hosting bulletproof infrastructure

`UC_12_1` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("stark-industries.solutions","the.hosting","worktitans.nl","pq.hosting","ufo.hosting","bill-migration-db.stark-industries.solutions","pq-ru.digitalvpn.org","pq.company") OR All_Traffic.dest="*.stark-industries.solutions" OR All_Traffic.dest="*.the.hosting" OR All_Traffic.dest="*.worktitans.nl" OR All_Traffic.dest="*.pq.hosting" OR All_Traffic.dest="*.ufo.hosting") by All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.action | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let StarkDomains = dynamic(["stark-industries.solutions","the.hosting","worktitans.nl","pq.hosting","ufo.hosting","bill-migration-db.stark-industries.solutions","pq-ru.digitalvpn.org","pq.company"]);
let StarkSuffixes = dynamic([".stark-industries.solutions",".the.hosting",".worktitans.nl",".pq.hosting",".ufo.hosting"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| extend HostLower = tolower(RemoteUrl)
| where HostLower in (StarkDomains) or HostLower has_any (StarkSuffixes)
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Hits=count(), Procs=make_set(InitiatingProcessFileName,10), Cmds=make_set(InitiatingProcessCommandLine,10), RemoteIPs=make_set(RemoteIP,10) by DeviceName, DeviceId, InitiatingProcessAccountName, HostLower
| order by FirstSeen asc
```

### [LLM] NoName057(16) DDoSia client beaconing to Stark / PQ-Hosting C2 ranges

`UC_12_2` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Traffic.dest_port) as dest_ports min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip IN ("45.140.17.0/24","45.140.147.0/24","77.83.197.0/24","77.221.156.0/24","193.27.12.0/22","194.36.190.0/24","185.225.17.0/24") AND NOT All_Traffic.app IN ("chrome","msedge","firefox","iexplore","brave")) by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest_ip All_Traffic.action | `drop_dm_object_name(All_Traffic)` | where count >= 5 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let StarkCidrs = dynamic(["45.140.17.0/24","45.140.147.0/24","77.83.197.0/24","77.221.156.0/24","193.27.12.0/22","194.36.190.0/24","185.225.17.0/24"]);
let BrowserBins = dynamic(["msedge.exe","chrome.exe","firefox.exe","iexplore.exe","brave.exe","opera.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIPType == "Public"
| where ipv4_is_in_any_range(RemoteIP, StarkCidrs)
| where InitiatingProcessFileName !in~ (BrowserBins)
| summarize Hits=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), DistinctDsts=dcount(RemoteIP), DstSample=make_set(RemoteIP,10), Ports=make_set(RemotePort,10), Cmds=make_set(InitiatingProcessCommandLine,5) by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath
| where Hits >= 5 or DistinctDsts >= 3
| order by Hits desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `stark-industries.solutions`, `the.hosting`, `worktitans.nl`, `pq.hosting`, `ufo.hosting`, `bill-migration-db.stark-industries.solutions`, `pq-ru.digitalvpn.org`, `pq.company` _(+2 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
