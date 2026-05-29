# [MED] From $5 Attacks to Botnet-Powered Platforms: Inside the DDoS-as-a- Service Market

**Source:** BleepingComputer
**Published:** 2026-05-29
**Article:** https://www.bleepingcomputer.com/news/security/from-5-attacks-to-botnet-powered-platforms-inside-the-ddos-as-a-service-market/

## Threat Profile

From $5 Attacks to Botnet-Powered Platforms: Inside the DDoS-as-a- Service Market 
Sponsored by Flare 
May 29, 2026
10:32 AM
0 


You have probably experienced the following scenario yourself. A website suddenly stops loading, a login page times out, or an online service becomes unreachable at the worst possible moment. Sometimes the cause is not an internal outage, but a Distributed Denial-of-Service ( DDoS ) attack designed to overwhelm the service from the outside.


DDoS attacks have lon…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `rebirthstress.cc`
- **Domain (defanged):** `rebirthstress.net`
- **Domain (defanged):** `satellitestress.st`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1583.005** — Acquire Infrastructure: Botnet
- **T1498** — Network Denial of Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Corporate endpoint contacts Flare-catalogued DDoS-as-a-Service booter panels (RebirthStress / SatelliteStress)

`UC_2_1` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url IN ("*rebirthstress.cc*","*rebirthstress.net*","*satellitestress.st*") OR Web.dest IN ("rebirthstress.cc","rebirthstress.net","satellitestress.st")) by Web.src Web.user Web.url Web.dest Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| append [
  | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query IN ("rebirthstress.cc","*.rebirthstress.cc","rebirthstress.net","*.rebirthstress.net","satellitestress.st","*.satellitestress.st") by DNS.src DNS.query
  | `drop_dm_object_name(DNS)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
]
| sort - lastTime
```

**Defender KQL:**
```kql
let BooterDomains = dynamic(["rebirthstress.cc","rebirthstress.net","satellitestress.st"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (BooterDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| union (
    DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("DnsQueryResponse","ConnectionSuccess")
    | where RemoteUrl has_any (BooterDomains) or AdditionalFields has_any (BooterDomains)
    | project Timestamp, DeviceName, InitiatingProcessAccountUpn=AccountName, InitiatingProcessAccountName=AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
)
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `rebirthstress.cc`, `rebirthstress.net`, `satellitestress.st`


## Why this matters

Severity classified as **MED** based on: IOCs present, 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
