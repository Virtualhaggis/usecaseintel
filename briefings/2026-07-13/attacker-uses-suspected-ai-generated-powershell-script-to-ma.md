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
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1482** — Domain Trust Discovery
- **T1005** — Data from Local System
- **T1135** — Network Share Discovery
- **T1069.002** — Permission Groups Discovery: Domain Groups
- **T1567.002** — Exfiltration to Cloud Storage
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1078** — Valid Accounts
- **T1074.001** — Data Staged: Local Data Staging
- **T1027** — Obfuscated/AI-Generated Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Bulk PowerShell/net.exe Active Directory enumeration (Get-AD* cmdlet flurry)

`UC_105_1` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process from datamodel=Endpoint.Processes where (Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe OR Processes.process_name=net.exe OR Processes.process_name=net1.exe) (Processes.process="*Get-ADUser*" OR Processes.process="*Get-ADComputer*" OR Processes.process="*Get-ADGroup*" OR Processes.process="*Get-ADOrganizationalUnit*" OR Processes.process="*Get-ADTrust*" OR Processes.process="*Get-ADDomainController*" OR Processes.process="*DirectorySearcher*" OR Processes.process="*nltest*" OR Processes.process="*net group*" OR Processes.process="*net user*") by Processes.dest Processes.user Processes.process_name span=5m | `drop_dm_object_name(Processes)` | where count>=3 | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe","net.exe","net1.exe")
| where AccountName !endswith "$"
| where ProcessCommandLine has_any ("Get-ADUser","Get-ADComputer","Get-ADGroup","Get-ADOrganizationalUnit","Get-ADTrust","Get-ADDomain","Get-ADDomainController","DirectorySearcher","nltest")
    or ProcessCommandLine matches regex @"(?i)\bnet1?\s+(group|user|accounts)\b"
| summarize Count=count(), Cmds=make_set(ProcessCommandLine,10), FirstSeen=min(Timestamp), Devices=make_set(DeviceName) by AccountName, bin(Timestamp, 5m)
| where Count >= 3   // 3+ distinct AD-discovery invocations in 5 min = bulk enumeration, not a one-off admin lookup
| order by FirstSeen desc
```

### AD Inventory report artifact written (AD_Report.html + staged CSV/zip)

`UC_105_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path from datamodel=Endpoint.Filesystem where Filesystem.file_name="AD_Report.html" by Filesystem.dest Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "AD_Report.html"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","cmd.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### SharpShares network share enumeration execution

`UC_105_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.process_name=SharpShares.exe OR Processes.process="*SharpShares*" OR Processes.original_file_name=SharpShares.exe) by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName =~ "SharpShares.exe"
    or ProcessVersionInfoOriginalFileName =~ "SharpShares.exe"
    or ProcessCommandLine has "SharpShares"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

### s5cmd bulk file tool execution (S3-compatible exfiltration)

`UC_105_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where (Processes.process_name=s5cmd.exe OR Processes.original_file_name=s5cmd.exe OR Processes.process="*s5cmd*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName =~ "s5cmd.exe" or ProcessVersionInfoOriginalFileName =~ "s5cmd.exe" or ProcessCommandLine has "s5cmd"
| where ProcessCommandLine has_any (" cp "," sync "," mv "," mb ","--endpoint-url","--profile") or FolderPath startswith @"C:\ProgramData\"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName
| order by Timestamp desc
```

### RDP interactive logon followed by tool execution staged in C:\ProgramData

`UC_105_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Endpoint.Processes where (Processes.process_path="C:\\ProgramData\\*" Processes.process_name="*.exe") OR (Processes.process_name IN (powershell.exe,pwsh.exe) Processes.process="*C:\\ProgramData*") by _time Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | join type=inner dest user [ | tstats `summariesonly` min(_time) as LogonTime from datamodel=Authentication where Authentication.authentication_method="RemoteInteractive" OR Authentication.logon_type=10 by Authentication.dest Authentication.user | `drop_dm_object_name(Authentication)` ] | where _time>=LogonTime AND _time<=LogonTime+7200 | table LogonTime _time dest user process_name process
```

**Defender KQL:**
```kql
let Window = 2h;
let RdpLogons = DeviceLogonEvents
    | where Timestamp > ago(7d)
    | where ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"
    | where AccountName !endswith "$"
    | project LogonTime = Timestamp, DeviceId, DeviceName, AccountName, RemoteIP;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FolderPath startswith @"C:\ProgramData\" and FileName endswith ".exe")
     or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has @"C:\ProgramData")
| join kind=inner RdpLogons on DeviceId, AccountName
| where Timestamp between (LogonTime .. LogonTime + Window)
| project LogonTime, ExecTime = Timestamp, DeviceName, AccountName, RemoteIP, FileName, FolderPath, ProcessCommandLine
| order by ExecTime desc
```

### Suspected AI-generated AD enumeration script content in PowerShell logs

`UC_105_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104) (ScriptBlockText="*100% Working AD Information Gathering Script*" OR ScriptBlockText="*FULLY FIXED*" OR ScriptBlockText="*AD Information Gathering Script*" OR (ScriptBlockText="*AD_Report.html*" AND ScriptBlockText="*DomainController*")) | stats count min(_time) as firstTime max(_time) as lastTime values(ScriptBlockText) as script by host, UserID | sort - lastTime
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

Severity classified as **CRIT** based on: 7 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
