# [HIGH] Beware of the license manager: how a Schneider Electric software vulnerability puts industrial facilities at risk

**Source:** Securelist (Kaspersky)
**Published:** 2026-06-26
**Article:** https://securelist.com/tr/schneider-electric-cve-2024-2658-vulnerability/120436/

## Threat Profile

Threat Response 
Table of Contents
About the vulnerability 
The role of FlexNet Publisher in Schneider Electric FLM 
The exploit path 
Mitigating CVE-2024-2658 
Detection with Kaspersky solutions 
Conclusion 
About the vulnerability 
The CVE-2024-2658 vulnerability was discovered in 2024 within the FlexNet Publisher component of the Schneider Electric Floating License Manager. This software handles license management across various Schneider Electric products used for comprehensive industrial au…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-2658`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1543.003** — Persistence (article-specific)
- **T1574** — Hijack Execution Flow
- **T1574.007** — Path Interception by PATH Environment Variable
- **T1574.001** — DLL Search Order Hijacking
- **T1574.002** — DLL Side-Loading
- **T1068** — Exploitation for Privilege Escalation
- **T1134.001** — Token Impersonation/Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Schneider FLM CVE-2024-2658: rogue openssl.cnf planted in hardcoded cygwin search path

`UC_75_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*cygwin\\home\\nightly*" OR (Filesystem.file_name="openssl.cnf" AND Filesystem.file_path="*\\contrib\\openssl*")) Filesystem.action IN ("created","modified","renamed") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.user Filesystem.process_id Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| where NOT match(user,"(?i)\$$") AND NOT lower(user) IN ("system","local service","network service")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"cygwin\home\nightly" or (FileName =~ "openssl.cnf" and FolderPath has @"\contrib\openssl")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessAccountName !in~ ("system","local service","network service")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### lmadmin.exe (Schneider FLM) loads DLL from user-writeable path — CVE-2024-2658 payload execution

`UC_75_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`sysmon` EventCode=7 Image="*\\lmadmin.exe" (ImageLoaded="*\\Users\\Public\\*" OR ImageLoaded="*\\Users\\*" OR ImageLoaded="*\\ProgramData\\*" OR ImageLoaded="*\\Windows\\Temp\\*" OR ImageLoaded="*\\cygwin\\*") NOT ImageLoaded="*\\Schneider Electric\\*"
| stats count min(_time) as firstTime max(_time) as lastTime values(ImageLoaded) as ImageLoaded values(Signed) as Signed by host Image ProcessId
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "lmadmin.exe"
| where FolderPath has_any (@"\Users\Public\", @"\Users\", @"\ProgramData\", @"\Windows\Temp\", @"\Temp\", @"\cygwin\")
| where FolderPath !has @"\Schneider Electric\"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessId
| order by Timestamp desc
```

### lmadmin.exe spawns shell/LOLBin or SYSTEM-integrity child — CVE-2024-2658 potato escalation

`UC_75_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="lmadmin.exe" AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","net.exe","net1.exe","whoami.exe","rundll32.exe","reg.exe","sc.exe","cscript.exe","wscript.exe","mshta.exe","certutil.exe","bitsadmin.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "lmadmin.exe"
| where FileName has_any ("cmd.exe","powershell.exe","pwsh.exe","net.exe","net1.exe","whoami.exe","rundll32.exe","reg.exe","sc.exe","cscript.exe","wscript.exe","mshta.exe","certutil.exe","bitsadmin.exe")
   or ProcessIntegrityLevel =~ "System"
   or AccountName =~ "system"
| project Timestamp, DeviceName, AccountName, ProcessIntegrityLevel, FileName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessId
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

### Article-specific behavioural hunt — Beware of the license manager: how a Schneider Electric software vulnerability p

`UC_75_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Beware of the license manager: how a Schneider Electric software vulnerability p ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("lmadmin.exe","malicious.dll") OR Processes.process_path="*C:\cygwin\home\nightly\LMADMI*" OR Processes.process_path="*C:\Users\public\malicious.dll*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\cygwin\home\nightly\LMADMI*" OR Filesystem.file_path="*C:\Users\public\malicious.dll*" OR Filesystem.file_name IN ("lmadmin.exe","malicious.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Beware of the license manager: how a Schneider Electric software vulnerability p
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("lmadmin.exe", "malicious.dll") or FolderPath has_any ("C:\cygwin\home\nightly\LMADMI", "C:\Users\public\malicious.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\cygwin\home\nightly\LMADMI", "C:\Users\public\malicious.dll") or FileName in~ ("lmadmin.exe", "malicious.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-2658`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 7 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
