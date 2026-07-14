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

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vibe-coded AD enum: PowerShell mass-exports CSVs + AD_Report.html to C:\ProgramData

`UC_45_1` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime dc(Filesystem.file_name) as file_count from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("powershell.exe","pwsh.exe") AND Filesystem.file_path="*\\ProgramData\\*" AND (Filesystem.file_name="AD_Report.html" OR Filesystem.file_name="*.csv") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | eval html_report=if(like(file_path,"%AD_Report.html%"),1,0) | where html_report=1 OR file_count>=5 | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where FolderPath has @"C:\ProgramData\"
| where FileName =~ "AD_Report.html" or FileName endswith ".csv"
| where InitiatingProcessAccountName !endswith "$"
| summarize FileCount = dcount(FileName), Files = make_set(FileName, 40),
            HtmlReport = countif(FileName =~ "AD_Report.html"),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
        by DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FolderPath
| where HtmlReport > 0 or FileCount >= 5   // 'exports a number of files, finally creates AD_Report.html'
| order by LastSeen desc
```

### s5cmd bulk-transfer tool executing on a domain-joined Windows server

`UC_45_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="s5cmd.exe" OR Processes.process="*s5cmd*") AND Processes.user!="*$" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.process_path | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "s5cmd.exe" or ProcessCommandLine has "s5cmd"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### SharpShares network-share enumeration utility execution

`UC_45_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="SharpShares.exe" OR Processes.process="*SharpShares*" OR Processes.original_file_name="SharpShares.exe") AND Processes.user!="*$" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "SharpShares.exe"
   or ProcessCommandLine has "SharpShares"
   or ProcessVersionInfoOriginalFileName =~ "SharpShares.exe"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine,
          ProcessVersionInfoOriginalFileName, SHA256, InitiatingProcessCommandLine
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

Severity classified as **CRIT** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
