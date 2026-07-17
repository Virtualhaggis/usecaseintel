# [CRIT] Researcher Drops New Windows Zero-Day PoC Hours After Microsoft Patch Tuesday

**Source:** The Hacker News
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
- **T1606.002** — Forge Web Credentials: SAML Tokens
- **T1068** — Exploitation for Privilege Escalation
- **T1112** — Modify Registry
- **T1134** — Access Token Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SharePoint IIS worker (w3wp.exe) spawning command/script interpreter — CVE-2026-56164/45659/32201 RCE

`UC_55_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="w3wp.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe","curl.exe","net.exe","net1.exe","whoami.exe","nltest.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","wscript.exe","cscript.exe","certutil.exe","bitsadmin.exe","curl.exe","net.exe","net1.exe","whoami.exe","nltest.exe")
| project Timestamp, DeviceName, AccountName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildImage = FolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### SharePoint web shell / .aspx payload written by w3wp.exe into LAYOUTS directory

`UC_55_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name="w3wp.exe" (Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.ashx" OR Filesystem.file_name="*.asmx") (Filesystem.file_path="*\\TEMPLATE\\LAYOUTS\\*" OR Filesystem.file_path="*\\Web Server Extensions\\*") by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName endswith ".aspx" or FileName endswith ".ashx" or FileName endswith ".asmx"
| where FolderPath has_any (@"TEMPLATE\LAYOUTS", "Web Server Extensions")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### LegacyHive EoP — cross-user UsrClass.dat mounted under another user's HKU\<SID>\_Classes

`UC_55_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*_Classes*" AND Registry.user!="SYSTEM" AND Registry.user!="*$" by Registry.dest Registry.user Registry.process_name Registry.registry_path | `drop_dm_object_name(Registry)` | rex field=registry_path "(?<KeySid>S-1-5-21-[0-9\-]+)_Classes" | where isnotnull(KeySid) | eval firstTime=strftime(firstTime,"%F %T") | table firstTime dest user process_name KeySid registry_path count | sort - firstTime
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has "_Classes"
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessAccountSid !in ("S-1-5-18","S-1-5-19","S-1-5-20")
| where InitiatingProcessIntegrityLevel in ("Medium","Low")
| extend KeySid = extract(@"(S-1-5-21-[0-9\-]+)_Classes", 1, RegistryKey)
| where isnotempty(KeySid)
| where InitiatingProcessAccountSid != KeySid
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessAccountSid,
          KeySid, RegistryKey, RegistryValueName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-56164`, `CVE-2026-56155`, `CVE-2026-32201`, `CVE-2026-45659`, `CVE-2026-55040`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
