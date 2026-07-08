# [HIGH] GitHub Secret Scanning Public Monitoring for Enterprises: Coverage and Gaps

**Source:** StepSecurity
**Published:** 2026-07-07
**Article:** https://www.stepsecurity.io/blog/github-secret-scanning-public-monitoring-for-enterprises-coverage-and-gaps

## Threat Profile

Back to Blog Resources GitHub Secret Scanning Public Monitoring for Enterprises: Coverage and Gaps GitHub's new public monitoring finds your enterprise's leaked secrets anywhere on github.com. Here is what it covers, what it cannot see, and how to close the exfiltration gap Eromosele Akhigbe View LinkedIn July 6, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
GitHub's new public monitoring finds your enterprise's leaked secre…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **IPv4 (defanged):** `45.139.104.115`
- **IPv4 (defanged):** `216.126.225.129`
- **Domain (defanged):** `bold-dhawan.45-139-104-115.plesk.page`
- **Domain (defanged):** `objective-hopper.45-139-104-115.plesk.page`
- **Domain (defanged):** `carte-avantage.com`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1567** — Exfiltration Over Web Service
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### GhostAction CI/CD secret exfiltration egress to attacker infrastructure

`UC_1_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_ip="45.139.104.115" OR All_Traffic.dest_ip="216.126.225.129" OR All_Traffic.dest="bold-dhawan.45-139-104-115.plesk.page" OR All_Traffic.dest="objective-hopper.45-139-104-115.plesk.page" OR All_Traffic.dest="carte-avantage.com") by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("45.139.104.115","216.126.225.129")
    or RemoteUrl has_any ("bold-dhawan.45-139-104-115.plesk.page","objective-hopper.45-139-104-115.plesk.page","carte-avantage.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, ActionType
| order by Timestamp desc
```

### GhostAction exfil-domain DNS resolution (blocked-egress early warning)

`UC_1_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="bold-dhawan.45-139-104-115.plesk.page" OR DNS.query="objective-hopper.45-139-104-115.plesk.page" OR DNS.query="carte-avantage.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| where RemoteUrl has_any ("bold-dhawan.45-139-104-115.plesk.page","objective-hopper.45-139-104-115.plesk.page","carte-avantage.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-30066`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `45.139.104.115`, `216.126.225.129`, `bold-dhawan.45-139-104-115.plesk.page`, `objective-hopper.45-139-104-115.plesk.page`, `carte-avantage.com`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
