# [HIGH] New Cisco DoS flaw requires manual reboot to revive devices

**Source:** BleepingComputer
**Published:** 2026-05-06
**Article:** https://www.bleepingcomputer.com/news/security/new-cisco-dos-flaw-requires-manual-reboot-to-revive-devices/

## Threat Profile

New Cisco DoS flaw requires manual reboot to revive devices 
By Sergiu Gatlan 
May 6, 2026
02:06 PM
0 


Cisco released security updates to fix a Crosswork Network Controller (CNC) and Network Services Orchestrator (NSO) denial-of-service (DoS) vulnerability that requires manually rebooting targeted systems for recovery.


Large enterprises and service providers leverage the CNC software suite to simplify multivendor network management and operations handling with automation, while the NSO o…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-20188`
- **CVE:** `CVE-2025-20362`
- **CVE:** `CVE-2025-20333`
- **CVE:** `CVE-2022-20653`
- **CVE:** `CVE-2024-20401`
- **CVE:** `CVE-2025-20115`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1499.004** — Endpoint Denial of Service: Application or System Exploitation
- **T1499.002** — Endpoint Denial of Service: Service Exhaustion Flood
- **T1498.001** — Network Denial of Service: Direct Network Flood

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Cisco CNC/NSO asset exposed to unauth DoS CVE-2026-20188

`UC_2_1` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as first_seen max(_time) as last_seen from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.signature="CVE-2026-20188" OR Vulnerabilities.cve="CVE-2026-20188" OR (Vulnerabilities.vendor="Cisco" AND (Vulnerabilities.product="*Crosswork Network Controller*" OR Vulnerabilities.product="*Network Services Orchestrator*" OR Vulnerabilities.product="*Cisco NSO*"))) by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.vendor Vulnerabilities.product Vulnerabilities.cvss
| `drop_dm_object_name(Vulnerabilities)`
| eval remediation="Upgrade Cisco CNC -> 7.2; Cisco NSO 6.4 -> 6.4.1.3 (NSO 6.5 not vulnerable)"
| sort - cvss
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId == "CVE-2026-20188"
   or (SoftwareVendor =~ "cisco" and (SoftwareName has "crosswork" or SoftwareName has "network services orchestrator" or SoftwareName has "cisco nso"))
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by VulnerabilitySeverityLevel desc, DeviceName asc
```

### [LLM] Connection-flood burst against Cisco CNC/NSO management interface (CVE-2026-20188 exploit candidate)

`UC_2_2` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_category="cisco_crosswork_cnc" OR All_Traffic.dest_category="cisco_nso" OR [|inputlookup cisco_cnc_nso_assets.csv | rename ip AS All_Traffic.dest | fields All_Traffic.dest]) AND All_Traffic.dest_port IN (443, 8080, 8443, 8888, 2022, 4569, 4570) AND All_Traffic.action!="blocked" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port _time span=1m
| `drop_dm_object_name(All_Traffic)`
| stats sum(count) as connections, dc(_time) as active_minutes, values(dest_port) as ports by src dest
| where connections > 1000 AND active_minutes >= 3
| eval cve="CVE-2026-20188", note="Sustained inbound connection burst toward Cisco CNC/NSO management endpoint - candidate connection-resource-exhaustion DoS"
| sort - connections
```

**Defender KQL:**
```kql
// Requires MDE Linux on the CNC/NSO appliance and a tagging convention so DeviceName / DeviceCategory identifies Cisco CNC/NSO assets
let cnc_nso_assets = DeviceInfo
    | where Timestamp > ago(1d)
    | where DeviceName has_any ("cnc","nso","crosswork") or Vendor =~ "cisco"
    | summarize make_set(DeviceId);
DeviceNetworkEvents
| where Timestamp > ago(2h)
| where ActionType in ("InboundConnectionAccepted","ConnectionAttempt","ConnectionSuccess")
| where DeviceId in (cnc_nso_assets)
| where LocalPort in (443, 8080, 8443, 8888, 2022, 4569, 4570)
| summarize Connections = count(),
            ActiveMinutes = dcount(bin(Timestamp, 1m)),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by DeviceName, RemoteIP, LocalPort, bin(Timestamp, 5m)
| where Connections > 200 and ActiveMinutes >= 3
| order by Connections desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-20188`, `CVE-2025-20362`, `CVE-2025-20333`, `CVE-2022-20653`, `CVE-2024-20401`, `CVE-2025-20115`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
