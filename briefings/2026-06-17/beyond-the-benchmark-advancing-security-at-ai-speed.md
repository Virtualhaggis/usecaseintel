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
- **T1595.002** — Vulnerability Scanning
- **T1059.003** — Windows Command Shell
- **T1059.001** — PowerShell
- **T1611** — Escape to Host
- **T1068** — Exploitation for Privilege Escalation
- **T1210** — Exploitation of Remote Services
- **T1499.004** — Application or System Exploitation
- **T1133** — External Remote Services
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### MDASH Patch-Tuesday cohort — unpatched Windows hosts (CVE-2026-45607/45641/47652/41108/45608/45634/45648/47289/45657/47291)

`UC_1_2` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-45607","CVE-2026-45641","CVE-2026-47652","CVE-2026-41108","CVE-2026-45608","CVE-2026-45634","CVE-2026-45648","CVE-2026-47289","CVE-2026-45657","CVE-2026-47291") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstSeen) ctime(lastSeen)
| sort - severity dest
```

**Defender KQL:**
```kql
let MdashCVEs = dynamic(["CVE-2026-45607","CVE-2026-45641","CVE-2026-47652","CVE-2026-41108","CVE-2026-45608","CVE-2026-45634","CVE-2026-45648","CVE-2026-47289","CVE-2026-45657","CVE-2026-47291"]);
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(2d)
| where CveId in (MdashCVEs)
| join kind=leftouter (DeviceInfo | where Timestamp > ago(2d) | summarize arg_max(Timestamp, OSPlatform, OSVersion, IsInternetFacing) by DeviceId) on DeviceId
| project DeviceName, OSPlatform, OSVersion, IsInternetFacing, CveId, VulnerabilitySeverityLevel, SoftwareName, SoftwareVersion, RecommendedSecurityUpdate
| order by IsInternetFacing desc, VulnerabilitySeverityLevel asc
```

### w3wp.exe / HTTP.sys post-exploitation child process (CVE-2026-47291 follow-up)

`UC_1_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","net.exe","whoami.exe") by Processes.dest Processes.parent_process_name Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe","wget.exe","net.exe","whoami.exe","hostname.exe","ipconfig.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Hyper-V vmwp.exe / vmms.exe spawning unexpected children — guest-to-host escape (CVE-2026-45607/45641/47652)

`UC_1_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as path from datamodel=Endpoint.Processes where (Processes.parent_process_name="vmwp.exe" OR Processes.parent_process_name="vmms.exe") Processes.process_name!="conhost.exe" Processes.process_name!="WerFault.exe" Processes.process_name!="vmcompute.exe" Processes.process_name!="vmwp.exe" Processes.process_name!="vmconnect.exe" by Processes.dest Processes.parent_process_name Processes.process_name Processes.user
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("vmwp.exe","vmms.exe")
| where FileName !in~ ("conhost.exe","WerFault.exe","vmcompute.exe","vmwp.exe","vmconnect.exe","WerFaultSecure.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Domain Controller lsass.exe / ntdsa.dll crash — CVE-2026-45648 AD DS stack overflow exploitation

`UC_1_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`wineventlog_application` EventCode=1000 (Faulting_application_name="lsass.exe" OR Faulting_module_name="ntdsa.dll" OR Faulting_module_name="ntdsai.dll") 
| eval is_dc=if(match(host,"(?i)dc[0-9]+|domain.*controller|adds"),"yes","unknown") 
| stats min(_time) as firstCrash max(_time) as lastCrash count by host Faulting_application_name Faulting_module_name Exception_code 
| where count >= 1 
| convert ctime(firstCrash) ctime(lastCrash)
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType in ("ProcessTerminated","AntivirusReport","ExploitGuardNonMicrosoftSignedBlocked") or AdditionalFields has "lsass"
| where InitiatingProcessFileName =~ "lsass.exe" or FileName =~ "lsass.exe" or AdditionalFields has_any ("ntdsa.dll","ntdsai.dll")
| join kind=inner (DeviceInfo | where Timestamp > ago(2d) | summarize arg_max(Timestamp, OSPlatform, MachineGroup, AdditionalFields) by DeviceId | where AdditionalFields has "DomainController" or MachineGroup has "DC" or AdditionalFields has "NTDS") on DeviceId
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

### Remote Desktop Client (mstsc.exe) crash following outbound RDP to untrusted host — CVE-2026-47289

`UC_1_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as conn_time values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="mstsc.exe" All_Traffic.dest_port=3389 by All_Traffic.src All_Traffic.user _time span=1m
| `drop_dm_object_name(All_Traffic)`
| join type=inner src [ search `wineventlog_application` EventCode=1000 Faulting_application_name="mstsc.exe" | rename host as src | eval crash_time=_time | table src crash_time Faulting_module_name Exception_code ]
| eval delta=crash_time-conn_time
| where delta>=0 AND delta<=120
| table src user dest_ip dest delta Faulting_module_name Exception_code
```

**Defender KQL:**
```kql
let RdpConns = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "mstsc.exe"
    | where RemotePort == 3389
    | where RemoteIPType == "Public"
    | project ConnTime=Timestamp, DeviceId, DeviceName, AccountName=InitiatingProcessAccountName, RemoteIP, RemoteUrl;
let Crashes = DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "ProcessTerminated" and InitiatingProcessFileName =~ "mstsc.exe"
    | project CrashTime=Timestamp, DeviceId, AdditionalFields;
RdpConns
| join kind=inner Crashes on DeviceId
| where CrashTime between (ConnTime .. ConnTime + 2m)
| project ConnTime, CrashTime, DelaySec=datetime_diff('second', CrashTime, ConnTime), DeviceName, AccountName, RemoteIP, RemoteUrl, AdditionalFields
| order by CrashTime desc
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

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
