# [HIGH] Microsoft patches RoguePlanet Defender zero-day vulnerability

**Source:** BleepingComputer
**Published:** 2026-07-09
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-rogueplanet-defender-zero-day-vulnerability/

## Threat Profile

Microsoft patches RoguePlanet Defender zero-day vulnerability 
By Sergiu Gatlan 
July 9, 2026
01:42 AM
0 
Microsoft has released a security patch to address a Defender zero-day vulnerability known as "RoguePlanet," disclosed after the June 2026 Patch Tuesday.
The flaw (tracked as CVE-2026-50656 ) was disclosed by a security researcher using the "Nightmare Eclipse" handle as part of an ongoing dispute with Microsoft over the company's bug bounty and vulnerability disclosure practices.
They also s…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-50656`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1068** — Exploitation for Privilege Escalation
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Microsoft Defender engine (MsMpEng.exe) overwriting System32\wermgr.exe — RoguePlanet CVE-2026-50656

`UC_17_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="wermgr.exe" Filesystem.file_path="*\\System32\\wermgr.exe" Filesystem.process_name="MsMpEng.exe" by Filesystem.dest Filesystem.process_name Filesystem.file_path Filesystem.action | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "wermgr.exe"
| where FolderPath has @"\System32\"
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, SHA256
| order by Timestamp desc
```

### Trojanized wermgr.exe spawning SYSTEM command shell — RoguePlanet privilege escalation

`UC_17_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="wermgr.exe" Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_integrity_level | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "wermgr.exe"
| where InitiatingProcessFolderPath has @"\System32\"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, AccountName, ProcessIntegrityLevel, Grandparent = InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Devices exposed to RoguePlanet — Malware Protection Engine below 1.1.26060.3008 (CVE-2026-50656)

`UC_17_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2026-50656"
| summarize arg_max(Timestamp, *) by DeviceId
| project Timestamp, DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-50656`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
