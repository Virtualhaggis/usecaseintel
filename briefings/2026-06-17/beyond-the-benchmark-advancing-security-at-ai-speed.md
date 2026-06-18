# [CRIT] Beyond the benchmark: Advancing security at AI speed

**Source:** Microsoft Security Blog
**Published:** 2026-06-17
**Article:** https://www.microsoft.com/en-us/security/blog/2026/06/17/beyond-the-benchmark-advancing-security-at-ai-speed/

## Threat Profile

Content types 
News 
Products and services 
Microsoft Defender 
Topics 
AI and agents 
Every vulnerability has two clocks running. One belongs to the defender racing to find it; the other to the cyberattacker hoping to find it first. For as long as software has existed, those clocks have favored the attacker, because modern code is vast, interconnected, and changing every day, while security reviews happen at fixed moments in time. The space between “code shipped” and “code reviewed” is where ri…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45607`
- **CVE:** `CVE-2026-45641`
- **CVE:** `CVE-2026-47652`
- **CVE:** `CVE-2026-41108`
- **CVE:** `CVE-2026-45608`
- **CVE:** `CVE-2026-45634`
- **CVE:** `CVE-2026-45648`
- **CVE:** `CVE-2026-47289`
- **CVE:** `CVE-2026-45657`
- **CVE:** `CVE-2026-47291`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1210** — Exploitation of Remote Services
- **T1068** — Exploitation for Privilege Escalation
- **T1203** — Exploitation for Client Execution
- **T1059.001** — PowerShell
- **T1611** — Escape to Host

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Hosts missing MDASH-discovered Patch Tuesday CVE-2026 fixes (Hyper-V, Kernel, AD DS, HTTP.sys, DNS/DHCP Client, RDP Client)

`UC_1_2` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-45607","CVE-2026-45641","CVE-2026-47652","CVE-2026-41108","CVE-2026-45608","CVE-2026-45634","CVE-2026-45648","CVE-2026-47289","CVE-2026-45657","CVE-2026-47291") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature
| `drop_dm_object_name(Vulnerabilities)`
| eval priority=case(cve=="CVE-2026-45657","P1-KernelUAF",cve=="CVE-2026-47291","P1-HTTPsys",cve=="CVE-2026-45648","P1-ADDS",cve=="CVE-2026-47289","P2-RDPClient",cve IN ("CVE-2026-45607","CVE-2026-45641","CVE-2026-47652"),"P2-HyperV",1=1,"P3")
| sort priority dest
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MDASH_CVEs = dynamic(["CVE-2026-45607","CVE-2026-45641","CVE-2026-47652","CVE-2026-41108","CVE-2026-45608","CVE-2026-45634","CVE-2026-45648","CVE-2026-47289","CVE-2026-45657","CVE-2026-47291"]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (MDASH_CVEs)
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, OSPlatform, OSVersion, IsInternetFacing, DeviceType) by DeviceId) on DeviceId
| extend Priority = case(
    CveId == "CVE-2026-45657", "P1-KernelUAF-9.8",
    CveId == "CVE-2026-47291", "P1-HTTPsys-9.8",
    CveId == "CVE-2026-45648", "P1-ADDS-DC-8.8",
    CveId == "CVE-2026-47289", "P2-RDPClient-8.8",
    CveId in ("CVE-2026-45607","CVE-2026-45641","CVE-2026-47652"), "P2-HyperV-8.x",
    "P3-DNS-DHCP")
| project Timestamp, Priority, DeviceName, DeviceId, OSPlatform, OSVersion, IsInternetFacing, CveId, VulnerabilitySeverityLevel, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| sort by Priority asc, DeviceName asc
```

### HTTP.sys integer-overflow RCE — unexpected child processes from w3wp.exe / svchost(http) on internet-facing hosts (CVE-2026-47291)

`UC_1_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="w3wp.exe" OR (Processes.parent_process_name="svchost.exe" AND Processes.parent_process IN ("*-k iissvcs*","*-k apppool*","*HTTP*"))) AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","net.exe","net1.exe","whoami.exe","nltest.exe","systeminfo.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessFileName =~ "w3wp.exe")
    or (InitiatingProcessFileName =~ "svchost.exe" and InitiatingProcessCommandLine has_any ("-k iissvcs","-k apppool","HTTP"))
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","net.exe","net1.exe","whoami.exe","nltest.exe","systeminfo.exe","ipconfig.exe","arp.exe","hostname.exe")
| join kind=leftouter (DeviceInfo | summarize arg_max(Timestamp, IsInternetFacing) by DeviceId) on DeviceId
| project Timestamp, DeviceName, IsInternetFacing, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Hyper-V guest escape — unexpected processes spawned by vmwp.exe or vmms.exe (CVE-2026-45607 / 45641 / 47652)

`UC_1_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("vmwp.exe","vmms.exe") AND NOT Processes.process_name IN ("vmcompute.exe","conhost.exe","WerFault.exe","WerFaultSecure.exe","vmwp.exe","vmms.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("vmwp.exe","vmms.exe")
| where FileName !in~ ("vmcompute.exe","conhost.exe","WerFault.exe","WerFaultSecure.exe","vmwp.exe","vmms.exe","vmconnect.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### AD DS stack-overflow RCE — lsass.exe spawning unexpected children on domain controllers (CVE-2026-45648)

`UC_1_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="lsass.exe" AND NOT Processes.process_name IN ("WerFault.exe","WerFaultSecure.exe","conhost.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| search dest IN ("*DC*","*dc*")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let DCs = DeviceInfo
    | where Timestamp > ago(7d)
    | where DeviceType =~ "Server" and (RegistryDeviceTag has "DomainController" or DeviceName matches regex @"(?i)(^|-)dc[0-9]*$")
    | summarize by DeviceId;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in (DCs)
| where InitiatingProcessFileName =~ "lsass.exe"
| where FileName !in~ ("WerFault.exe","WerFaultSecure.exe","conhost.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256, InitiatingProcessIntegrityLevel
| order by Timestamp desc
```

### Article-specific behavioural hunt — Beyond the benchmark: Advancing security at AI speed

`UC_1_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Beyond the benchmark: Advancing security at AI speed ```
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
// Article-specific bespoke detection — Beyond the benchmark: Advancing security at AI speed
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
  - CVE(s): `CVE-2026-45607`, `CVE-2026-45641`, `CVE-2026-47652`, `CVE-2026-41108`, `CVE-2026-45608`, `CVE-2026-45634`, `CVE-2026-45648`, `CVE-2026-47289` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
