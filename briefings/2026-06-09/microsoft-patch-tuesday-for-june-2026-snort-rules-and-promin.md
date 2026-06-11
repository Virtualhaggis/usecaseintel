# [CRIT] Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilities

**Source:** Cisco Talos
**Published:** 2026-06-09
**Article:** https://blog.talosintelligence.com/microsoft-patch-tuesday-for-june-2026-snort-rules-and-prominent-vulnerabilities/

## Threat Profile

Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilities 
By 
Chetan Raghuprasad 
Tuesday, June 9, 2026 17:21
Patch Tuesday
Microsoft has released its monthly security update for June 2026, which includes 206 vulnerabilities affecting a range of products, including 32 that Microsoft marked as “critical”. 
Out of 32 "critical" entries, 28 are remote code execution (RCE) vulnerabilities in Microsoft Windows services and applications including Windows Active Directory, Wind…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42985`
- **CVE:** `CVE-2026-47291`
- **CVE:** `CVE-2026-44803`
- **CVE:** `CVE-2026-44812`
- **CVE:** `CVE-2026-42992`
- **CVE:** `CVE-2026-44799`
- **CVE:** `CVE-2026-44801`
- **CVE:** `CVE-2026-47289`
- **CVE:** `CVE-2026-48563`
- **CVE:** `CVE-2026-45607`
- **CVE:** `CVE-2026-45641`
- **CVE:** `CVE-2026-47652`
- **CVE:** `CVE-2026-45657`
- **CVE:** `CVE-2026-48574`
- **CVE:** `CVE-2026-42987`
- **CVE:** `CVE-2026-44815`
- **CVE:** `CVE-2026-45456`
- **CVE:** `CVE-2026-45458`
- **CVE:** `CVE-2026-47635`
- **CVE:** `CVE-2026-45461`
- **CVE:** `CVE-2026-45463`
- **CVE:** `CVE-2026-45472`
- **CVE:** `CVE-2026-45474`
- **CVE:** `CVE-2026-45476`
- **CVE:** `CVE-2026-44810`
- **CVE:** `CVE-2026-47644`
- **CVE:** `CVE-2026-26142`
- **CVE:** `CVE-2026-32193`
- **CVE:** `CVE-2026-45648`
- **CVE:** `CVE-2026-47288`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1543.003** — Persistence (article-specific)
- **T1203** — Exploitation for Client Execution
- **T1210** — Exploitation of Remote Services
- **T1219** — Remote Access Software
- **T1611** — Escape to Host
- **T1610** — Deploy Container

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Microsoft June 2026 Patch Tuesday — exposure to 'exploitation more likely' critical CVEs

`UC_42_2` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as firstSeen max(_time) as lastSeen count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-42985","CVE-2026-47291","CVE-2026-44803","CVE-2026-44812") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity 
| `drop_dm_object_name(Vulnerabilities)` 
| eval cve_priority=case(cve=="CVE-2026-47291","1-critical-http.sys-net-RCE",cve=="CVE-2026-42985","2-critical-RDP-client-RCE",cve=="CVE-2026-44803" OR cve=="CVE-2026-44812","3-critical-Win32k-GRFX-RCE",1==1,"4-critical") 
| convert ctime(firstSeen) ctime(lastSeen) 
| sort 0 cve_priority dest
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(2d)
| where CveId in ("CVE-2026-42985","CVE-2026-47291","CVE-2026-44803","CVE-2026-44812")
| summarize arg_max(Timestamp, *) by CveId, DeviceId
| extend Priority = case(
    CveId == "CVE-2026-47291", "1-http.sys-network-RCE",
    CveId == "CVE-2026-42985", "2-RDP-client-RCE",
    CveId in ("CVE-2026-44803","CVE-2026-44812"), "3-Win32k-GRFX-RCE",
    "4-critical")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing, OSPlatform, OSVersion) by DeviceId) on DeviceId
| project Timestamp, Priority, CveId, DeviceName, OSPlatform, OSVersion, IsInternetFacing, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by Priority asc, IsInternetFacing desc, DeviceName asc
```

### mstsc.exe spawns unexpected child process — RDP Client RCE post-exploit (CVE-2026-42985 + 5 related)

`UC_42_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as processCmd values(Processes.process_path) as processPath values(Processes.parent_process) as parentCmd from datamodel=Endpoint.Processes where Processes.parent_process_name="mstsc.exe" AND NOT Processes.process_name IN ("conhost.exe","rdpclip.exe","tabtip.exe","mstsc.exe","WerFault.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "mstsc.exe"
| where FileName !in~ ("conhost.exe","rdpclip.exe","tabtip.exe","mstsc.exe","werfault.exe","werfaultsecure.exe")
| where AccountName !endswith "$"
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFileName =~ "mstsc.exe"
    | where RemotePort == 3389
    | summarize RdpDestIP = make_set(RemoteIP, 5), RdpDestUrl = make_set(RemoteUrl, 5) by DeviceId, InitiatingProcessId
  ) on $left.DeviceId == $right.DeviceId, $left.InitiatingProcessId == $right.InitiatingProcessId
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          ChildIntegrity = ProcessIntegrityLevel,
          SHA256, RdpDestIP, RdpDestUrl
| order by Timestamp desc
```

### AKS pod with hostNetwork:true in non-system namespace — CVE-2026-32193 container escape risk

`UC_42_4` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`kube_audit_index` sourcetype IN ("kube:apiserver:audit","kube:audit") verb=create objectRef.resource=pods 
| where NOT objectRef.namespace IN ("kube-system","kube-public","kube-node-lease","gatekeeper-system","calico-system","tigera-operator") 
| spath input=requestObject path=spec.hostNetwork output=hostNetwork 
| spath input=requestObject path=spec.hostPID output=hostPID 
| spath input=requestObject path=spec.hostIPC output=hostIPC 
| where hostNetwork="true" 
| table _time user.username objectRef.namespace objectRef.name hostNetwork hostPID hostIPC sourceIPs{} 
| sort -_time
```

### Article-specific behavioural hunt — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie

`UC_42_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("http.sys"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("http.sys"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft Patch Tuesday for June 2026 — Snort rules and prominent vulnerabilitie
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("http.sys"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("http.sys"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-42985`, `CVE-2026-47291`, `CVE-2026-44803`, `CVE-2026-44812`, `CVE-2026-42992`, `CVE-2026-44799`, `CVE-2026-44801`, `CVE-2026-47289` _(+22 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
