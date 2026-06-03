# [HIGH] CISA warns of cyberattacks targeting fuel tank monitoring systems

**Source:** BleepingComputer
**Published:** 2026-06-03
**Article:** https://www.bleepingcomputer.com/news/security/cisa-warns-of-cyberattacks-targeting-fuel-tank-monitoring-systems/

## Threat Profile

CISA warns of cyberattacks targeting fuel tank monitoring systems 
By Lawrence Abrams 
June 3, 2026
04:21 PM
0 


CISA, the FBI, the NSA, the Department of Energy, and other US government partners are warning that hackers are targeting internet-exposed automatic tank gauge (ATG) systems used to monitor fuel and liquid storage tanks across various critical infrastructure sectors.


The cybersecurity agency says that ATG systems are commonly used in the Energy, Chemical, Food and Agriculture, …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-45066`
- **CVE:** `CVE-2024-43693`
- **CVE:** `CVE-2024-43423`
- **CVE:** `CVE-2024-8310`
- **CVE:** `CVE-2024-6981`
- **CVE:** `CVE-2024-43692`
- **CVE:** `CVE-2024-8630`
- **CVE:** `CVE-2024-41725`
- **CVE:** `CVE-2024-45373`
- **CVE:** `CVE-2024-8497`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1592.002** — Gather Victim Host Information: Software

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Internet-exposed ATG TCP/10001 (Veeder-Root TCP/IP Interface Module) inbound

`UC_2_1` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=10001 AND All_Traffic.transport=tcp AND All_Traffic.action IN ("allowed","accept","permit") AND NOT (All_Traffic.src_ip=10.0.0.0/8 OR All_Traffic.src_ip=172.16.0.0/12 OR All_Traffic.src_ip=192.168.0.0/16) by All_Traffic.src_ip, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.app, All_Traffic.action | `drop_dm_object_name(All_Traffic)` | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where LocalPort == 10001 and Protocol == "Tcp"
| where ActionType in ("InboundConnectionAccepted","ListeningConnectionCreated","ConnectionAcknowledged")
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] ProGauge MAGLINK LX CONSOLE UTILITY command injection (CVE-2024-43693)

`UC_2_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_method="POST" AND (Web.url="*utility*" OR Web.url="*Utility*" OR Web.url="*/sd/*" OR Web.url="*UtilityPage*") by Web.src, Web.dest, Web.url, Web.http_user_agent, Web.status, Web.http_method | `drop_dm_object_name(Web)` | rex field=url "(?<suspicious_meta>[;&|`]|\$\(|%3B|%7C|%60|%24%28)" | where isnotnull(suspicious_meta) OR status>=500 | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S")
```

### [LLM] Vulnerable ATG/fuel-monitoring software in TVM inventory (CISA June 2026 CVEs)

`UC_2_3` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2024-45066","CVE-2024-43693","CVE-2024-43423","CVE-2024-8310","CVE-2024-6981","CVE-2024-43692","CVE-2024-8630","CVE-2024-41725") by Vulnerabilities.dest, Vulnerabilities.cve, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.vendor_product | `drop_dm_object_name(Vulnerabilities)` | eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S") | sort - severity
```

**Defender KQL:**
```kql
let ATG_CVES = dynamic(["CVE-2024-45066","CVE-2024-43693","CVE-2024-43423","CVE-2024-8310","CVE-2024-6981","CVE-2024-43692","CVE-2024-8630","CVE-2024-41725"]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (ATG_CVES)
| join kind=leftouter (DeviceInfo | where Timestamp > ago(1d) | summarize arg_max(Timestamp,*) by DeviceId | project DeviceId, IsInternetFacing, PublicIP, LoggedOnUsers, MachineGroup) on DeviceId
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing, PublicIP, MachineGroup
| order by IsInternetFacing desc, VulnerabilitySeverityLevel asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-45066`, `CVE-2024-43693`, `CVE-2024-43423`, `CVE-2024-8310`, `CVE-2024-6981`, `CVE-2024-43692`, `CVE-2024-8630`, `CVE-2024-41725` _(+2 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
