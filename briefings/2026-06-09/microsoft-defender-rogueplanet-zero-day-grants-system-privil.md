# [HIGH] Microsoft Defender 'RoguePlanet' zero-day grants SYSTEM privileges

**Source:** BleepingComputer
**Published:** 2026-06-09
**Article:** https://www.bleepingcomputer.com/news/microsoft/microsoft-defender-rogueplanet-zero-day-grants-system-privileges/

## Threat Profile

Microsoft Defender 'RoguePlanet' zero-day grants SYSTEM privileges 
By Lawrence Abrams 
June 9, 2026
07:11 PM
0 
A security researcher has released a new Microsoft Defender zero-day exploit named "RoguePlanet" just hours after Microsoft fixed two previously disclosed flaws during June 2026 Patch Tuesday.
The researcher, known as Nightmare Eclipse, says the new vulnerability affects fully patched Windows 10 and Windows 11 devices, allowing attackers to spawn a command prompt with SYSTEM privilege…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33825`
- **Domain (defanged):** `projectnightcrawler.dev`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1071** — Application Layer Protocol
- **T1068** — Exploitation for Privilege Escalation
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1204.002** — User Execution: Malicious File
- **T1080** — Taint Shared Content
- **T1105** — Ingress Tool Transfer
- **T1588.005** — Obtain Capabilities: Exploits
- **T1574.005** — Hijack Execution Flow: Executable Installer File Permissions Weakness

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SYSTEM cmd.exe spawned by Defender MsMpEng.exe (RoguePlanet LPE artifact)

`UC_38_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="MsMpEng.exe" Processes.process_name="cmd.exe" by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_integrity_level | `drop_dm_object_name(Processes)` | where like(user,"%SYSTEM%") OR process_integrity_level="system" | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where FileName =~ "cmd.exe"
| where ProcessIntegrityLevel =~ "System" or AccountName =~ "system"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          ProcessIntegrityLevel, SHA256
| order by Timestamp desc
```

### Defender engine reads .vhd/.vhdx/.iso from remote SMB share (RoguePlanet RCE vector)

`UC_38_3` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name="MsMpEng.exe" OR Filesystem.process_name="mpengine.dll") (Filesystem.file_name="*.vhd" OR Filesystem.file_name="*.vhdx" OR Filesystem.file_name="*.iso" OR Filesystem.file_name="*.vmdk") Filesystem.file_path="\\\\*" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where FolderPath startswith @"\\\\" or RequestProtocol =~ "SMB"
| where FileName has_any (".vhd", ".vhdx", ".iso", ".vmdk")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, FolderPath, FileName,
          RequestProtocol, RequestSourceIP, ShareName, SHA256
| order by Timestamp desc
```

### Host resolves or connects to projectnightcrawler.dev (RoguePlanet PoC repository)

`UC_38_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="*projectnightcrawler.dev*" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count from datamodel=Web.Web where Web.url="*projectnightcrawler.dev*" by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` ]
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has "projectnightcrawler.dev"
  | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            RemoteUrl, RemoteIP, RemotePort, Source="Network"),
(DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse"
  | where AdditionalFields has "projectnightcrawler.dev"
  | project Timestamp, DeviceName, AccountName,
            InitiatingProcessFileName, InitiatingProcessCommandLine,
            RemoteUrl=tostring(parse_json(AdditionalFields).DnsQueryString),
            RemoteIP="", RemotePort=int(null), Source="DNS")
| order by Timestamp desc
```

### Junction or reparse point created targeting Defender ProgramData scan path

`UC_38_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="fsutil.exe" OR Processes.process_name="mklink.exe") (Processes.process="*mklink /J*" OR Processes.process="*mklink /D*" OR Processes.process="*fsutil reparsepoint*" OR Processes.process="*New-Item*-ItemType SymbolicLink*" OR Processes.process="*New-Item*-ItemType Junction*") (Processes.process="*\\ProgramData\\Microsoft\\Windows Defender*" OR Processes.process="*\\ProgramFiles\\Windows Defender*" OR Processes.process="*mpengine*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","fsutil.exe")
| where ProcessCommandLine has_any ("mklink /J","mklink /D","fsutil reparsepoint","New-Item -ItemType SymbolicLink","New-Item -ItemType Junction")
| where ProcessCommandLine has_any (@"\ProgramData\Microsoft\Windows Defender", @"\Program Files\Windows Defender", "mpengine", "MsMpEng")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          FileName, ProcessCommandLine, ProcessIntegrityLevel
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33825`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `projectnightcrawler.dev`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 6 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
