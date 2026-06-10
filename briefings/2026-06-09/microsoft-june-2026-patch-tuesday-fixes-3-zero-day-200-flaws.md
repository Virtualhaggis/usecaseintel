# [CRIT] Microsoft June 2026 Patch Tuesday fixes 3 zero-day, 200 flaws

**Source:** BleepingComputer
**Published:** 2026-06-09
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-june-2026-patch-tuesday-fixes-3-zero-day-200-flaws/

## Threat Profile

Microsoft June 2026 Patch Tuesday fixes 3 zero-day, 200 flaws 
By Lawrence Abrams 
June 9, 2026
01:57 PM
0 
Today is Microsoft's June 2026 Patch Tuesday, with security updates for 200 flaws and three publicly disclosed zero-day vulnerabilities.
This Patch Tuesday addresses 33 "Critical" vulnerabilities, 28 of which are remote code execution, 4 are elevation of privilege, and 1 is an information disclosure flaw.
The number of bugs in each vulnerability category is listed below:
65 Elevation of Pr…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-45586`
- **CVE:** `CVE-2026-49160`
- **CVE:** `CVE-2026-50507`
- **CVE:** `CVE-2026-45585`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1204.002** — User Execution: Malicious File
- **T1006** — Direct Volume Access
- **T1542** — Pre-OS Boot
- **T1499.003** — Endpoint Denial of Service: Application Exhaustion Flood
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1068** — Exploitation for Privilege Escalation
- **T1499** — Endpoint Denial of Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### BitLocker YellowKey (CVE-2026-50507) — Shell Spawned in WinRE/WinPE Context

`UC_14_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="winpeshl.exe" OR Processes.parent_process_path="*\\winpeshl.exe" OR Processes.process_path="X:\\*") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe") by host Processes.dest Processes.user Processes.parent_process_name Processes.parent_process_path Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName =~ "winpeshl.exe"
      or FolderPath startswith @"X:\"
      or InitiatingProcessFolderPath startswith @"X:\")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","reagentc.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### HTTP/2 Bomb (CVE-2026-49160) — MaxHeadersCount Mitigation Posture

`UC_14_8` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as values_observed from datamodel=Endpoint.Registry where Registry.registry_path="*\\Services\\HTTP\\Parameters*" AND Registry.registry_value_name="MaxHeadersCount" by Registry.dest Registry.user Registry.process_name Registry.registry_path Registry.registry_value_name | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
// Forward-pivot: hosts where the KB5102602 mitigation was applied. Invert against your IIS/HTTP.sys server inventory to find exposed gaps.
DeviceRegistryEvents
| where Timestamp > ago(90d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"Services\HTTP\Parameters"
      and RegistryValueName =~ "MaxHeadersCount"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(1d)
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, IsInternetFacing) by DeviceId, DeviceName
  ) on DeviceName
| order by Timestamp desc
```

### June 2026 Patch Tuesday Zero-Day Exposure Inventory (CVE-2026-45586/49160/50507)

`UC_14_9` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-45586","CVE-2026-49160","CVE-2026-50507","CVE-2026-45648","CVE-2026-45491","CVE-2026-45490","CVE-2026-45591","CVE-2026-47643","CVE-2026-41098","CVE-2026-42836","CVE-2026-45482") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | sort severity desc, dest
```

**Defender KQL:**
```kql
let TargetCves = dynamic(["CVE-2026-45586","CVE-2026-49160","CVE-2026-50507","CVE-2026-45648","CVE-2026-45491","CVE-2026-45490","CVE-2026-45591","CVE-2026-47643","CVE-2026-41098","CVE-2026-42836","CVE-2026-45482"]);
DeviceTvmSoftwareVulnerabilities
| where CveId in (TargetCves)
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, IsInternetFacing, MachineGroup) by DeviceId, DeviceName
  ) on DeviceId
| join kind=leftouter (
    DeviceTvmSoftwareVulnerabilitiesKB
    | project CveId, CvssScore, IsExploitAvailable, VulnerabilityDescription
  ) on CveId
| summarize ExposedDevices = dcount(DeviceId),
            InternetFacingExposed = dcountif(DeviceId, IsInternetFacing == true),
            SampleDevices = make_set(DeviceName, 25)
            by CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId, CvssScore, IsExploitAvailable
| order by InternetFacingExposed desc, ExposedDevices desc
```

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### Article-specific behavioural hunt — Microsoft June 2026 Patch Tuesday fixes 3 zero-day, 200 flaws

`UC_14_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft June 2026 Patch Tuesday fixes 3 zero-day, 200 flaws ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("http.sys","fdwsd.dll","uxtheme.dll","uiamanager.dll","upnp.dll","wininet.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("http.sys","fdwsd.dll","uxtheme.dll","uiamanager.dll","upnp.dll","wininet.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Microsoft June 2026 Patch Tuesday fixes 3 zero-day, 200 flaws
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("http.sys", "fdwsd.dll", "uxtheme.dll", "uiamanager.dll", "upnp.dll", "wininet.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("http.sys", "fdwsd.dll", "uxtheme.dll", "uiamanager.dll", "upnp.dll", "wininet.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-45586`, `CVE-2026-49160`, `CVE-2026-50507`, `CVE-2026-45585`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
