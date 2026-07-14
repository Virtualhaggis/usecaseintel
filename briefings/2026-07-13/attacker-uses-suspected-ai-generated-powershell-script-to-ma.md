# [CRIT] Attacker Uses Suspected AI-Generated PowerShell Script to Map Active Directory

**Source:** The Hacker News
**Published:** 2026-07-13
**Article:** https://thehackernews.com/2026/07/attacker-uses-suspected-ai-generated.html

## Threat Profile

Attacker Uses Suspected AI-Generated PowerShell Script to Map Active Directory 
 Ravie Lakshmanan  Jul 13, 2026 Artificial Intelligence / Threat Intelligence 
Cybersecurity researchers have flagged an intrusion in which an unknown threat actor leveraged a vibe-coded PowerShell script for Active Directory (AD) enumeration.
"The script looked for the Domain Controller (DC) and mapped users, computers, and domains, before creating a directory and exporting out a number of files, and finally creat…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1087.002** — Account Discovery: Domain Account
- **T1018** — Remote System Discovery
- **T1482** — Domain Trust Discovery
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1135** — Network Share Discovery
- **T1083** — File and Directory Discovery
- **T1567.002** — Exfiltration to Cloud Storage
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1074.001** — Data Staged: Local Data Staging
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AI-generated 'FULLY FIXED' PowerShell AD enumeration writing AD_Report.html

`UC_51_1` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="AD_Report.html" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id 
| `drop_dm_object_name(Filesystem)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where FileName =~ "AD_Report.html"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256
| order by Timestamp desc
```

### SharpShares network-share enumeration binary staged in C:\ProgramData

`UC_51_2` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="SharpShares.exe" OR Processes.original_file_name="SharpShares.exe" OR (Processes.process_path="C:\\ProgramData\\*" AND Processes.process="*shares*")) by Processes.dest Processes.user Processes.process_name Processes.original_file_name Processes.process Processes.process_path Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "SharpShares.exe"
    or ProcessVersionInfoOriginalFileName =~ "SharpShares.exe"
    or (FolderPath startswith "C:\\ProgramData\\" and ProcessCommandLine has "shares" and ProcessCommandLine has_any ("--ldap","--filter","--outfile","/ldap","/outfile"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### s5cmd bulk cloud-storage exfiltration tool executed from C:\ProgramData

`UC_51_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="s5cmd.exe" OR Processes.original_file_name="s5cmd.exe") (Processes.process="*cp*" OR Processes.process="*sync*" OR Processes.process="*mv*" OR Processes.process="*s3://*" OR Processes.process="*--endpoint-url*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "s5cmd.exe" or ProcessVersionInfoOriginalFileName =~ "s5cmd.exe"
| where ProcessCommandLine has_any ("cp","sync","mv","s3://","--endpoint-url")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Executable in C:\ProgramData root launched within an RDP session (attacker tool staging)

`UC_51_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_path="C:\\ProgramData\\*" Processes.process_name="*.exe" by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)` 
| where match(process_path, "(?i)^C:\\\\ProgramData\\\\[^\\\\]+\.exe$") 
| `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let RdpLogons = DeviceLogonEvents
| where Timestamp > ago(7d)
| where LogonType == "RemoteInteractive"
| where AccountName !endswith "$"
| project RdpTime = Timestamp, DeviceId, RdpUser = AccountName, RemoteIP;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FolderPath matches regex @"(?i)^C:\\ProgramData\\[^\\]+\.exe$"
| join kind=inner RdpLogons on DeviceId
| where Timestamp between (RdpTime .. RdpTime + 12h)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, RdpTime, RdpUser, RemoteIP
| order by Timestamp desc
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


## Why this matters

Severity classified as **CRIT** based on: 5 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
