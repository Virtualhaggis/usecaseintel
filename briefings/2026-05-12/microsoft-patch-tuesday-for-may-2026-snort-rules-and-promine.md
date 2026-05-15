# [HIGH] Microsoft Patch Tuesday for May 2026 — Snort rules and prominent vulnerabilities

**Source:** Cisco Talos
**Published:** 2026-05-12
**Article:** https://blog.talosintelligence.com/microsoft-patch-tuesday-may-2026/

## Threat Profile

Microsoft Patch Tuesday for May 2026 — Snort rules and prominent vulnerabilities 
By 
Jaeson Schultz 
Tuesday, May 12, 2026 15:57
Patch Tuesday
By   Jaeson Schultz  
Microsoft has released its monthly security update for May 2026, which includes 137 vulnerabilities affecting a range of products, including 31 that Microsoft marked as “critical”. 
In this month's release, Microsoft has not observed any of the included vulnerabilities being actively exploited in the wild. Out of 31 "critical" entri…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-32161`
- **CVE:** `CVE-2026-33109`
- **CVE:** `CVE-2026-33844`
- **CVE:** `CVE-2026-35421`
- **CVE:** `CVE-2026-40358`
- **CVE:** `CVE-2026-40361`
- **CVE:** `CVE-2026-40363`
- **CVE:** `CVE-2026-40364`
- **CVE:** `CVE-2026-40365`
- **CVE:** `CVE-2026-40366`
- **CVE:** `CVE-2026-40367`
- **CVE:** `CVE-2026-40403`
- **CVE:** `CVE-2026-41089`
- **CVE:** `CVE-2026-41096`
- **CVE:** `CVE-2026-42831`
- **CVE:** `CVE-2026-42898`
- **CVE:** `CVE-2026-33835`
- **CVE:** `CVE-2026-33837`
- **CVE:** `CVE-2026-33840`
- **CVE:** `CVE-2026-33841`
- **CVE:** `CVE-2026-35416`
- **CVE:** `CVE-2026-35417`
- **CVE:** `CVE-2026-40369`
- **CVE:** `CVE-2026-40397`
- **CVE:** `CVE-2026-40398`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1219** — Remote Access Software
- **T1203** — Exploitation for Client Execution
- **T1566.001** — Phishing: Spearphishing Attachment

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Asset hunt: devices missing May 2026 Patch Tuesday critical fixes

`UC_78_1` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-32161","CVE-2026-33109","CVE-2026-33844","CVE-2026-35421","CVE-2026-40358","CVE-2026-40361","CVE-2026-40363","CVE-2026-40364","CVE-2026-40365","CVE-2026-40366","CVE-2026-40367","CVE-2026-40403","CVE-2026-41089","CVE-2026-41096","CVE-2026-42831","CVE-2026-42898","CVE-2026-33835","CVE-2026-33837","CVE-2026-33840","CVE-2026-33841","CVE-2026-35416","CVE-2026-35417","CVE-2026-40369","CVE-2026-40397","CVE-2026-40398") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstSeen) ctime(lastSeen)
| sort 0 -severity dest
```

**Defender KQL:**
```kql
let MayPatchTuesday2026 = dynamic([
  "CVE-2026-32161","CVE-2026-33109","CVE-2026-33844","CVE-2026-35421",
  "CVE-2026-40358","CVE-2026-40361","CVE-2026-40363","CVE-2026-40364",
  "CVE-2026-40365","CVE-2026-40366","CVE-2026-40367","CVE-2026-40403",
  "CVE-2026-41089","CVE-2026-41096","CVE-2026-42831","CVE-2026-42898",
  "CVE-2026-33835","CVE-2026-33837","CVE-2026-33840","CVE-2026-33841",
  "CVE-2026-35416","CVE-2026-35417","CVE-2026-40369","CVE-2026-40397",
  "CVE-2026-40398"
]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (MayPatchTuesday2026)
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform, OSVersion, MachineGroup) by DeviceId
  ) on DeviceId
| summarize MissingCves = make_set(CveId),
            MaxSeverity = max(VulnerabilitySeverityLevel),
            Software = make_set(strcat(SoftwareVendor, " ", SoftwareName, " ", SoftwareVersion)),
            RecommendedKBs = make_set(RecommendedSecurityUpdate)
            by DeviceName, DeviceId, IsInternetFacing, OSPlatform, MachineGroup
| extend Priority = iff(IsInternetFacing == true, "P1-Internet-Facing", "P2-Internal")
| order by Priority asc, MaxSeverity desc
```

### [LLM] CVE-2026-40403: outbound mstsc.exe RDP session to non-corporate IP (vulnerable RDP Client → attacker server)

`UC_78_2` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as dest_ports values(All_Traffic.user) as user from datamodel=Network_Traffic where All_Traffic.app="mstsc.exe" AND All_Traffic.dest_port=3389 NOT (All_Traffic.dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16)) by All_Traffic.src All_Traffic.dest_ip
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| iplocation dest_ip
| sort 0 -lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "mstsc.exe"
| where RemoteIPType == "Public"
| where RemotePort in (3389, 443)
| where ActionType in ("ConnectionSuccess", "ConnectionAttempt")
| where not(ipv4_is_in_any_range(RemoteIP, dynamic(["100.64.0.0/10","169.254.0.0/16"])))
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Connections = count()
            by DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort, InitiatingProcessCommandLine
| where Connections >= 1
| order by FirstSeen desc
```

### [LLM] CVE-2026-35421: Microsoft Paint (mspaint.exe) opening Enhanced Metafile (.emf)

`UC_78_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.process_command_line) as cmdline from datamodel=Endpoint.Processes where Processes.process_name="mspaint.exe" (Processes.process="*.emf*" OR Processes.process="*.EMF*") by Processes.dest Processes.user Processes.process_path
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort 0 -lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "mspaint.exe"
| where ProcessCommandLine matches regex @"(?i)\.emf(\"|\s|$)"
| extend EmfPath = extract(@"(?i)([A-Za-z]:\\[^\"]+\.emf)", 1, ProcessCommandLine)
| extend Sourced_From = case(
    EmfPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\", @"\INetCache\", @"\Outlook\"), "Untrusted-Origin",
    EmfPath has @"\Public\", "Public-Folder",
    "Other")
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          EmfPath, Sourced_From, ProcessCommandLine, SHA256
| order by Sourced_From asc, Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-32161`, `CVE-2026-33109`, `CVE-2026-33844`, `CVE-2026-35421`, `CVE-2026-40358`, `CVE-2026-40361`, `CVE-2026-40363`, `CVE-2026-40364` _(+17 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
