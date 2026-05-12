# [CRIT] UAT-4356's Targeting of Cisco Firepower Devices

**Source:** Cisco Talos
**Published:** 2026-04-23
**Article:** https://blog.talosintelligence.com/uat-4356-firestarter/

## Threat Profile

UAT-4356's Targeting of Cisco Firepower Devices 
By 
Cisco Talos 
Thursday, April 23, 2026 11:10
Threat Advisory
Threats
APT
Cisco Talos is aware of UAT-4356 's continued active targeting of Cisco Firepower devices’ Firepower eXtensible Operating System (FXOS). UAT-4356 exploited n-day vulnerabilities ( CVE-2025-20333 and CVE-2025-20362 ) to gain unauthorized access to vulnerable devices, where the threat actor deployed their custom-built backdoor dubbed “FIRESTARTER.” FIRESTARTER considerably o…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-20333`
- **CVE:** `CVE-2025-20362`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1601.001** — Modify System Image: Patch System Image
- **T1543** — Create or Modify System Process
- **T1055** — Process Injection
- **T1588.006** — Obtain Capabilities: Vulnerabilities

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] FIRESTARTER backdoor on-device strings in Cisco ASA/FTD/FXOS syslog (UAT-4356)

`UC_149_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`cisco_asa` OR `cisco_ftd` OR (sourcetype IN ("cisco:asa","cisco:fxos","cisco:ftd","cisco:ios")) ("lina_cs" OR "svc_samcore.log" OR "CSP_MOUNT_LIST" OR "CSP_MOUNTLIST.tmp" OR "/usr/bin/lina_cs" OR "/opt/cisco/platform/logs/var/log/svc_samcore.log")
| eval indicator=case(match(_raw,"(?i)/usr/bin/lina_cs"),"FIRESTARTER_binary_path", match(_raw,"(?i)/opt/cisco/platform/logs/var/log/svc_samcore.log"),"FIRESTARTER_backup_path", match(_raw,"(?i)CSP_MOUNT(LIST|_LIST)"),"CSP_MOUNT_LIST_persistence", match(_raw,"(?i)\\blina_cs\\b"),"lina_cs_process", true(),"other")
| stats min(_time) as firstSeen max(_time) as lastSeen count values(indicator) as indicators values(_raw) as raw_samples by host, src, sourcetype
| convert ctime(firstSeen) ctime(lastSeen)
| `get_asset(host)`
| sort 0 - count
```

**Defender KQL:**
```kql
// Defender XDR has no direct visibility into Cisco appliance internals.
// This query covers two fallback angles: (1) Linux endpoints onboarded to Defender that act as syslog collectors / staging hops for Cisco logs, (2) any Linux endpoint where the FIRESTARTER paths might appear (rare, but cheap to check).
union isfuzzy=true
(
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has_any (@"/usr/bin/lina_cs", @"/opt/cisco/platform/logs/var/log/svc_samcore.log", @"/opt/cisco/platform/logs/var/log")
        or FileName in~ ("lina_cs", "svc_samcore.log", "CSP_MOUNTLIST.tmp")
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
),
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "lina_cs"
        or ProcessCommandLine has_any ("CSP_MOUNT_LIST", "CSP_MOUNTLIST.tmp", "/usr/bin/lina_cs", "svc_samcore.log")
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
)
| order by Timestamp desc
```

### [LLM] Cisco ASA/FTD assets exposed to CVE-2025-20333 / CVE-2025-20362 (UAT-4356 entry vectors)

`UC_149_3` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2025-20333","CVE-2025-20362") by Vulnerabilities.dest, Vulnerabilities.dest_category, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.cve, Vulnerabilities.cvss
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstSeen) ctime(lastSeen)
| eval priority=case(severity=="critical" OR cvss>=9, "P1_reimage_candidate", true(), "P2_patch")
| sort 0 - cvss, dest
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2025-20333", "CVE-2025-20362")
| where SoftwareVendor =~ "cisco" or SoftwareName has_any ("asa","firepower","ftd","fxos","adaptive_security_appliance")
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | project DeviceId, IsInternetFacing, PublicIP, MachineGroup, OSPlatform
  ) on DeviceId
| project DeviceName, DeviceId, IsInternetFacing, PublicIP, MachineGroup, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | project CveId, CvssScore, IsExploitAvailable, PublishedDate
  ) on CveId
| extend Priority = iff(IsInternetFacing == true or VulnerabilitySeverityLevel =~ "Critical", "P1_reimage_candidate", "P2_patch")
| order by Priority asc, CvssScore desc
```

### Article-specific behavioural hunt — UAT-4356's Targeting of Cisco Firepower Devices

`UC_149_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — UAT-4356's Targeting of Cisco Firepower Devices ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/opt/cisco/platform/logs/var/log/svc_samcore.log*" OR Filesystem.file_path="*/usr/bin/lina_cs*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — UAT-4356's Targeting of Cisco Firepower Devices
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/opt/cisco/platform/logs/var/log/svc_samcore.log", "/usr/bin/lina_cs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-20333`, `CVE-2025-20362`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
