# [CRIT] Microsoft June 2026 Patch Tuesday fixes 6 zero-days, 200 flaws

**Source:** BleepingComputer
**Published:** 2026-06-09
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-june-2026-patch-tuesday-fixes-6-zero-days-200-flaws/

## Threat Profile

Microsoft June 2026 Patch Tuesday fixes 6 zero-days, 200 flaws 
By Lawrence Abrams 
June 9, 2026
01:57 PM
0 
Article and title updated as 3 additional zero-days were fixed in the June 2026 Patch Tuesday. 
Today is Microsoft's June 2026 Patch Tuesday, with security updates for 200 flaws, including five publicly disclosed zero-day vulnerabilities and one actively exploited in attacks.
This Patch Tuesday addresses 33 "Critical" vulnerabilities, 28 of which are remote code execution, 4 are elevation…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-42897`
- **CVE:** `CVE-2026-45585`
- **CVE:** `CVE-2026-45586`
- **CVE:** `CVE-2026-49160`
- **CVE:** `CVE-2026-50507`
- **CVE:** `CVE-2020-17103`

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
- **T1068** — Exploitation for Privilege Escalation
- **T1542.003** — Pre-OS Boot: Bootkit
- **T1490** — Inhibit System Recovery
- **T1006** — Direct Volume Access
- **T1499.003** — Endpoint Denial of Service: Application Exhaustion Flood

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Hunt for unpatched hosts exposed to June 2026 Patch Tuesday zero-days

`UC_41_7` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-45586","CVE-2026-49160","CVE-2026-45585","CVE-2026-50507","CVE-2020-17103","CVE-2026-42897") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity
| `drop_dm_object_name(Vulnerabilities)`
| stats dc(dest) as AffectedHosts values(dest) as Hosts values(severity) as Severity min(firstSeen) as FirstSeen max(lastSeen) as LastSeen by cve
| eval ActivelyExploited=if(cve=="CVE-2026-42897","YES","no")
| sort - ActivelyExploited - AffectedHosts
| convert ctime(FirstSeen) ctime(LastSeen)
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-45586","CVE-2026-49160","CVE-2026-45585","CVE-2026-50507","CVE-2020-17103","CVE-2026-42897")
| summarize AffectedHosts = dcount(DeviceId),
            HostsSample = make_set(DeviceName, 50),
            Severity = any(VulnerabilitySeverityLevel),
            RecommendedKB = any(RecommendedSecurityUpdate),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
            by CveId, SoftwareName, SoftwareVendor
| extend ActivelyExploited = iff(CveId == "CVE-2026-42897", "YES — prioritise", "no")
| order by ActivelyExploited desc, AffectedHosts desc
```

### Suspicious reagentc.exe and WinRE boot configuration manipulation (YellowKey / bitskrieg context)

`UC_41_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="reagentc.exe" (Processes.process="*\/boottore*" OR Processes.process="*\/setreimage*" OR Processes.process="*\/disable*" OR Processes.process="*\/enable*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process
| `drop_dm_object_name(Processes)`
| where NOT user IN ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE") AND NOT match(user,"\\$$")
| where NOT parent_process_name IN ("mmc.exe","MsMpEng.exe","SenseIR.exe","TrustedInstaller.exe")
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "reagentc.exe"
| where ProcessCommandLine has_any ("/boottore","/setreimage","/disable","/enable","/setbootshelllink")
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
| where InitiatingProcessFileName !in~ ("mmc.exe","MsMpEng.exe","SenseIR.exe","TrustedInstaller.exe","TiWorker.exe")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildCmd    = ProcessCommandLine,
          IsRemoteSession = InitiatingProcessAccountName != AccountName
| order by Timestamp desc
```

### HTTP/2 Bomb mitigation posture - MaxHeadersCount registry baseline

`UC_41_9` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\HTTP\\Parameters*" Registry.registry_value_name="MaxHeadersCount" by Registry.dest Registry.registry_value_data Registry.registry_value_name Registry.process_name
| `drop_dm_object_name(Registry)`
| stats values(registry_value_data) as ConfiguredValue values(process_name) as SetByProcess min(firstTime) as FirstSeen max(lastTime) as LastSeen by dest
| eval MitigationStatus=case(isnull(ConfiguredValue),"MISSING - vulnerable", tonumber(ConfiguredValue)>1000,"SET but too high",1=1,"OK")
| convert ctime(FirstSeen) ctime(LastSeen)
| sort MitigationStatus dest
```

**Defender KQL:**
```kql
let ConfiguredHosts = DeviceRegistryEvents
    | where Timestamp > ago(90d)
    | where RegistryKey has @"SYSTEM\CurrentControlSet\Services\HTTP\Parameters"
    | where RegistryValueName =~ "MaxHeadersCount"
    | summarize ConfiguredValue = arg_max(Timestamp, RegistryValueData),
                LastSet = max(Timestamp),
                SetByProcess = any(InitiatingProcessFileName)
                by DeviceId, DeviceName;
DeviceInfo
| where Timestamp > ago(1d)
| summarize arg_max(Timestamp, *) by DeviceId
| where OSPlatform startswith "Windows" and (OSPlatform has "Server" or IsInternetFacing == true)
| join kind=leftouter ConfiguredHosts on DeviceId
| extend MitigationStatus = case(
    isempty(ConfiguredValue), "MISSING - vulnerable to HTTP/2 Bomb",
    toint(ConfiguredValue) > 1000, strcat("SET but high (", ConfiguredValue, ") — review"),
    "OK")
| project DeviceName, OSPlatform, IsInternetFacing, MitigationStatus, ConfiguredValue, LastSet, SetByProcess
| order by MitigationStatus asc, DeviceName asc
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

### Article-specific behavioural hunt — Microsoft June 2026 Patch Tuesday fixes 6 zero-days, 200 flaws

`UC_41_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Microsoft June 2026 Patch Tuesday fixes 6 zero-days, 200 flaws ```
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
// Article-specific bespoke detection — Microsoft June 2026 Patch Tuesday fixes 6 zero-days, 200 flaws
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
  - CVE(s): `CVE-2026-42897`, `CVE-2026-45585`, `CVE-2026-45586`, `CVE-2026-49160`, `CVE-2026-50507`, `CVE-2020-17103`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
