# [HIGH] CISA warns of cyberattacks disrupting U.S. water utilities

**Source:** BleepingComputer
**Published:** 2026-07-31
**Article:** https://www.bleepingcomputer.com/news/security/cisa-warns-of-cyberattacks-disrupting-us-water-utilities/

## Threat Profile

CISA warns of cyberattacks disrupting U.S. water utilities 
By Bill Toulas 
July 31, 2026
12:49 PM
0 
The U.S. Cybersecurity and Infrastructure Security Agency (CISA) is warning of a significant increase in attacks targeting internet-exposed programmable logic controllers (PLCs) in the water and wastewater systems sector.
The agency's urgent alert comes after hackers disrupted more than 30 community water systems in Minnesota in attacks that started last Sunday and continued through Monday.
CISA…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-22681`
- **CVE:** `CVE-2023-3595`
- **CVE:** `CVE-2024-6242`
- **IPv4 (defanged):** `185.82.73.160`
- **IPv4 (defanged):** `185.82.73.161`
- **IPv4 (defanged):** `185.82.73.162`
- **IPv4 (defanged):** `185.82.73.163`
- **IPv4 (defanged):** `185.82.73.164`
- **IPv4 (defanged):** `185.82.73.165`
- **IPv4 (defanged):** `185.82.73.166`
- **IPv4 (defanged):** `185.82.73.168`
- **IPv4 (defanged):** `185.82.73.169`
- **IPv4 (defanged):** `185.82.73.170`
- **IPv4 (defanged):** `185.82.73.171`
- **IPv4 (defanged):** `135.136.1.133`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T0883** — Internet Accessible Device
- **T0886** — Remote Services
- **T0819** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Network communication with Iranian-APT infrastructure targeting Rockwell PLCs (185.82.73.160-171 / 135.136.1.133)

`UC_5_2` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("185.82.73.160","185.82.73.161","185.82.73.162","185.82.73.163","185.82.73.164","185.82.73.165","185.82.73.166","185.82.73.168","185.82.73.169","185.82.73.170","185.82.73.171","135.136.1.133") OR All_Traffic.src IN ("185.82.73.160","185.82.73.161","185.82.73.162","185.82.73.163","185.82.73.164","185.82.73.165","185.82.73.166","185.82.73.168","185.82.73.169","185.82.73.170","185.82.73.171","135.136.1.133")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.transport All_Traffic.direction | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let iocIPs = dynamic(["185.82.73.160","185.82.73.161","185.82.73.162","185.82.73.163","185.82.73.164","185.82.73.165","185.82.73.166","185.82.73.168","185.82.73.169","185.82.73.170","185.82.73.171","135.136.1.133"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (iocIPs)
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Inbound EtherNet/IP (TCP 44818) or TCP 2222 to OT assets from the public internet

`UC_5_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (44818,2222) All_Traffic.direction="inbound" NOT (All_Traffic.src IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")) by All_Traffic.dest All_Traffic.dest_port All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "InboundConnectionAccepted"
| where LocalPort in (44818, 2222)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-22681`, `CVE-2023-3595`, `CVE-2024-6242`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.82.73.160`, `185.82.73.161`, `185.82.73.162`, `185.82.73.163`, `185.82.73.164`, `185.82.73.165`, `185.82.73.166`, `185.82.73.168` _(+4 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
