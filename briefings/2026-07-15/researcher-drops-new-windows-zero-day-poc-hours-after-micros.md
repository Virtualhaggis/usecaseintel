# [CRIT] Researcher Drops New Windows Zero-Day PoC Hours After Microsoft Patch Tuesday

**Source:** The Hacker News, BleepingComputer
**Published:** 2026-07-15
**Article:** https://thehackernews.com/2026/07/researcher-drops-new-windows-zero-day.html

## Threat Profile

Researcher Drops New Windows Zero-Day PoC Hours After Microsoft Patch Tuesday 
 Ravie Lakshmanan  Jul 15, 2026 Vulnerability / Enterprise Security 
Security researcher Chaotic Eclipse (aka Nightmare-Eclipse ) has released a new proof-of-concept (PoC) exploit called LegacyHive.
It has been described as a Windows User Profile Service arbitrary hive load elevation of privileges vulnerability. The Windows User Profile Service, also referred to as ProfSvc, is a core system component that manages us…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-56164`
- **CVE:** `CVE-2026-56155`
- **CVE:** `CVE-2026-32201`
- **CVE:** `CVE-2026-45659`
- **CVE:** `CVE-2026-55040`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1505.003** — Server Software Component: Web Shell
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1068** — Exploitation for Privilege Escalation
- **T1112** — Modify Registry

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SharePoint IIS worker (w3wp.exe) spawning command interpreter — CVE-2026-56164/55040 RCE

`UC_1_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=w3wp.exe (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","cscript.exe","wscript.exe","certutil.exe","bitsadmin.exe","curl.exe","net.exe","net1.exe","whoami.exe","rundll32.exe","regsvr32.exe")) by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where InitiatingProcessCommandLine has "SharePoint"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","cscript.exe","wscript.exe","certutil.exe","bitsadmin.exe","curl.exe","net.exe","net1.exe","whoami.exe","rundll32.exe","regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### ASPX webshell / malware dropped into SharePoint LAYOUTS by w3wp.exe

`UC_1_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*Web Server Extensions*TEMPLATE\\LAYOUTS*") (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.ashx" OR Filesystem.file_name="*.asmx") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FolderPath has "Web Server Extensions" and FolderPath has @"TEMPLATE\LAYOUTS"
| where FileName endswith ".aspx" or FileName endswith ".ashx" or FileName endswith ".asmx" or FileName endswith ".aspx.cs"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

### LegacyHive — cross-user UsrClass.dat hive load via User Profile Service (ProfSvc EoP)

`UC_1_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="UsrClass.dat" (Filesystem.file_path="*\\AppData\\Local\\Microsoft\\Windows*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | search process_name!="svchost.exe" process_name!="System" process_name!="wininit.exe" | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName =~ "UsrClass.dat" or PreviousFileName =~ "UsrClass.dat"
| where FolderPath has @"\AppData\Local\Microsoft\Windows"
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where InitiatingProcessFileName !in~ ("svchost.exe","wininit.exe","lsass.exe","explorer.exe","System")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessAccountName !in~ ("system","local service","network service")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName, PreviousFolderPath
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-56164`, `CVE-2026-56155`, `CVE-2026-32201`, `CVE-2026-45659`, `CVE-2026-55040`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
