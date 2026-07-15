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
- **T1068** — Exploitation for Privilege Escalation
- **T1112** — Modify Registry
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1505.003** — Server Software Component: Web Shell
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### LegacyHive: cross-user registry hive (UsrClass.dat/NTUSER.dat) load via User Profile Service

`UC_6_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="UsrClass.dat" OR Filesystem.file_name="NTUSER.dat") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_id Filesystem.user | `drop_dm_object_name(Filesystem)` | rex field=file_path "(?i)\\Users\\(?<profile_user>[^\\]+)\\" | where isnotnull(profile_user) AND NOT (profile_user IN ("Public","Default","Default User","All Users")) AND lower(profile_user)!=lower(user) AND NOT match(user,"\$$") | table firstTime lastTime dest user profile_user file_name file_path process_name
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName in~ ("UsrClass.dat","NTUSER.dat")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessAccountName !in~ ("system","local service","network service")
| extend ProfileUser = tostring(extract(@"(?i)\\Users\\([^\\]+)\\", 1, FolderPath))
| where isnotempty(ProfileUser)
| where ProfileUser !in~ ("Public","Default","Default User","All Users")
| where tolower(ProfileUser) != tolower(InitiatingProcessAccountName)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ProfileUser, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId
| order by Timestamp desc
```

### SharePoint IIS worker (w3wp) spawning command shell — post-RCE execution (CVE-2026-56164/32201/45659)

`UC_6_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="w3wp.exe" OR Processes.parent_process_name="owstimer.exe") AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","cscript.exe","wscript.exe","certutil.exe","bitsadmin.exe","net.exe","net1.exe","whoami.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT match(user,"\$$") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("w3wp.exe","owstimer.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","cscript.exe","wscript.exe","certutil.exe","bitsadmin.exe","net.exe","net1.exe","whoami.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### SharePoint webshell (.aspx) written by w3wp into LAYOUTS — persistence / machine-key theft

`UC_6_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name="w3wp.exe" OR Filesystem.process_name="owstimer.exe") AND (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.ashx" OR Filesystem.file_name="*.asmx") AND (Filesystem.file_path="*\\TEMPLATE\\LAYOUTS*" OR Filesystem.file_path="*Web Server Extensions*" OR Filesystem.file_path="*\\wwwroot\\wss*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("w3wp.exe","owstimer.exe")
| where FileName endswith ".aspx" or FileName endswith ".ashx" or FileName endswith ".asmx"
| where FolderPath has_any (@"\TEMPLATE\LAYOUTS", @"\Web Server Extensions\", @"\wwwroot\wss\", @"\inetpub\wwwroot")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-56164`, `CVE-2026-56155`, `CVE-2026-32201`, `CVE-2026-45659`, `CVE-2026-55040`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
