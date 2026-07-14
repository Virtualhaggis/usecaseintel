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
- **T1482** — Domain Trust Discovery
- **T1018** — Remote System Discovery
- **T1567.002** — Exfiltration to Cloud Storage
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1135** — Network Share Discovery
- **T1021.001** — Remote Services: Remote Desktop Protocol
- **T1078** — Valid Accounts
- **T1059.001** — Command and Scripting Interpreter: PowerShell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vibe-coded AD enumeration report artifacts written by PowerShell (AD_*.csv + AD_Report.html)

`UC_39_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_names dc(Filesystem.file_name) as file_count from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("AD_Users.csv","AD_Computers.csv","AD_Groups.csv","AD_OUs.csv","AD_Subnets.csv","AD_Trusts.csv","AD_Users_With_Email.csv","AD_Simple_Users.csv","AD_Report.html","DNS_Subnets.txt") OR Filesystem.file_path="C:\\AD_Reports_*") by Filesystem.dest Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | where file_count>=3 | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName in~ ("AD_Users.csv","AD_Computers.csv","AD_Groups.csv","AD_OUs.csv","AD_Subnets.csv","AD_Trusts.csv","AD_Users_With_Email.csv","AD_Simple_Users.csv","AD_Report.html","DNS_Subnets.txt")
   or FolderPath startswith @"C:\AD_Reports_"
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| summarize FileNames=make_set(FileName), FileCount=dcount(FileName), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), ScriptCmd=any(InitiatingProcessCommandLine) by DeviceName, InitiatingProcessAccountName, FolderPath
| where FileCount >= 3
| order by LastSeen desc
```

### s5cmd.exe staged in C:\ProgramData used for bulk exfiltration on Windows

`UC_39_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process_name) as parent_process_name min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="s5cmd.exe" OR Processes.process="*s5cmd*" OR Processes.process_path="C:\\ProgramData\\s5cmd.exe") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "s5cmd.exe" or ProcessVersionInfoOriginalFileName =~ "s5cmd.exe" or ProcessCommandLine has "s5cmd"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, IsInitiatingProcessRemoteSession
| order by Timestamp desc
```

### SharpShares.exe network share enumeration post-AD-recon

`UC_39_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process_name) as parent_process_name min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="SharpShares.exe" OR Processes.process="*SharpShares*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "SharpShares.exe" or ProcessVersionInfoOriginalFileName =~ "SharpShares.exe" or ProcessCommandLine has "SharpShares"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, IsInitiatingProcessRemoteSession
| order by Timestamp desc
```

### RDP interactive logon followed by tool execution staged in C:\ProgramData

`UC_39_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_path="C:\\ProgramData\\*" OR Processes.process="*C:\\ProgramData\\*" OR Processes.process="*C:\\ProgramData\\Untitled1.ps1*") by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let Window = 2h;
let RdpLogons = DeviceLogonEvents
    | where Timestamp > ago(14d)
    | where ActionType == "LogonSuccess" and LogonType == "RemoteInteractive"
    | where AccountName !endswith "$"
    | project LogonTime = Timestamp, DeviceId, RdpUser = AccountName, RemoteIP;
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FolderPath startswith @"C:\ProgramData\" or ProcessCommandLine has @"C:\ProgramData\"
| where AccountName !endswith "$"
| join kind=inner RdpLogons on DeviceId
| where Timestamp between (LogonTime .. LogonTime + Window)
| project LogonTime, ExecTime = Timestamp, DeviceName, RdpUser, RemoteIP, AccountName, FileName, FolderPath, ProcessCommandLine
| order by ExecTime desc
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

Severity classified as **CRIT** based on: 5 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
