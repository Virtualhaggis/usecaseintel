# [HIGH] Hackers disrupt over 30 Minnesota water utilities in coordinated OT attack

**Source:** BleepingComputer
**Published:** 2026-07-29
**Article:** https://www.bleepingcomputer.com/news/security/hackers-target-over-30-minnesota-water-utilities-in-coordinated-ot-attack/

## Threat Profile

Hackers target over 30 Minnesota water utilities in coordinated OT attack 
By Ionut Ilascu 
July 29, 2026
10:55 AM
0 
Source: Blue Lake Wastewater Treatment 
The Minnesota IT Services (MNIT) agency activated its cybersecurity incident response capabilities across the entire state after hackers targeted more than 30 community water systems in “a coordinated cyberattack.”
​The attacks occurred on Sunday and Monday, July 26 and 27, and targeted operational technology (OT) systems at local water uti…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-22681`
- **CVE:** `CVE-2023-3595`
- **CVE:** `CVE-2024-6242`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T0819** — Exploit Public-Facing Application (ICS)
- **T0883** — Internet Accessible Device
- **T0866** — Exploitation of Remote Services
- **T0827** — Loss of Control
- **T0828** — Loss of Productivity and Revenue

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Inbound OT-segment connections from CyberAv3ngers infrastructure (185.82.73.160/28, 135.136.1.133)

`UC_9_1` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.src IN ("185.82.73.160","185.82.73.161","185.82.73.162","185.82.73.163","185.82.73.164","185.82.73.165","185.82.73.166","185.82.73.167","185.82.73.168","185.82.73.169","185.82.73.170","185.82.73.171","135.136.1.133") OR All_Traffic.dest IN ("185.82.73.160","185.82.73.161","185.82.73.162","185.82.73.163","185.82.73.164","185.82.73.165","185.82.73.166","185.82.73.167","185.82.73.168","185.82.73.169","185.82.73.170","185.82.73.171","135.136.1.133")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.action | `drop_dm_object_name(All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ipv4_is_in_range(RemoteIP, "185.82.73.160/28") or RemoteIP == "135.136.1.133"
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Internet-sourced access to OT/ICS PLCs on EtherNet/IP, Modbus & S7comm ports

`UC_9_2` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (44818,2222,502,102,20000,47808) AND All_Traffic.src_category!="internal" AND All_Traffic.action="allowed" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | where NOT cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("172.16.0.0/12",src) AND NOT cidrmatch("192.168.0.0/16",src) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (44818, 2222, 502, 102, 20000, 47808)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessFileName
| order by Timestamp desc
```

### Vulnerable Rockwell/Allen-Bradley MicroLogix PLCs exposed to campaign CVEs

`UC_9_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2021-22681", "CVE-2023-3595", "CVE-2024-6242")
| project DeviceId, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, PublicIP) by DeviceId) on DeviceId
| order by IsInternetFacing desc, CveId asc
```

### Coordinated fan-out from CyberAv3ngers infrastructure across multiple OT sites

`UC_9_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(All_Traffic.dest_port) as dest_ports dc(All_Traffic.dest) as distinct_targets min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.src IN ("185.82.73.160","185.82.73.161","185.82.73.162","185.82.73.163","185.82.73.164","185.82.73.165","185.82.73.166","185.82.73.167","185.82.73.168","185.82.73.169","185.82.73.170","185.82.73.171","135.136.1.133")) by All_Traffic.src span=1h | `drop_dm_object_name(src)` | where distinct_targets >= 3 | sort - distinct_targets
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ipv4_is_in_range(RemoteIP, "185.82.73.160/28") or RemoteIP == "135.136.1.133"
| summarize DistinctHosts = dcount(DeviceName), Hosts = make_set(DeviceName, 50), Ports = make_set(LocalPort, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteIP, bin(Timestamp, 1h)
| where DistinctHosts >= 3   // 3+ distinct internal OT hosts hit by one attacker IP in 1h = coordinated fan-out
| order by DistinctHosts desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-22681`, `CVE-2023-3595`, `CVE-2024-6242`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 5 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
