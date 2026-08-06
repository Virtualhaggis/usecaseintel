# [CRIT] Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-07-17
**Article:** https://unit42.paloaltonetworks.com/siemens-rox-ii-zero-day-vulnerabilities/

## Threat Profile

Threat Research Center 
Threat Research 
Vulnerabilities 
Vulnerabilities 
Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy 
9 min read 
Related Products Advanced Threat Prevention Cloud-Delivered Security Services Industrial and Operational Technology IoT Security Next-Generation Firewall 
By: Emmanuel Zhou 
Adam Robbie 
Rick Wyble 
Miguel Pereira 
Published: July 17, 2026 
Categories: Threat Research 
Vulnerabilities 
Tags: Command injection 
CVE-2025-40947 
CVE-2025-40948 
CVE-2…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-40947`
- **CVE:** `CVE-2025-40948`
- **CVE:** `CVE-2025-40949`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1005** — Data from Local System
- **T1053.003** — Scheduled Task/Job: Cron
- **T1543** — Create or Modify System Process

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Siemens RUGGEDCOM ROX II devices exposed to CVE-2025-40947/48/49 (firmware < V2.17.1)

`UC_207_4` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2025-40947", "CVE-2025-40948", "CVE-2025-40949")
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### Siemens ROX II xz utility misused as cat to read root-owned secrets (CVE-2025-40948)

`UC_207_5` · phase: **actions** · confidence: **Low** · AI-generated for this article

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "xz"
| where ProcessCommandLine has_any ("-dc", "--stdout", "-d -c", "--decompress", "--format=raw")
| where ProcessCommandLine has_any ("/etc/shadow", "/etc/passwd", "id_rsa", "/etc/ssh", "/etc/ssl", ".key", "private", "/etc/confd", "/etc/rox")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Siemens ROX II root cron table injection via web task scheduler (CVE-2025-40949)

`UC_207_6` · phase: **install** · confidence: **Low** · AI-generated for this article

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any ("/var/spool/cron/crontabs", "/etc/cron.d/", "/etc/crontab", "/var/spool/cron/root")
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Article-specific behavioural hunt — Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy

`UC_207_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy ```
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/rev_shell.py*")
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Three Steps to the Terminal: A Siemens ROX II Zero-Day Trilogy
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/rev_shell.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-40947`, `CVE-2025-40948`, `CVE-2025-40949`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
