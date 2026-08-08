# [HIGH] Swiss government SharePoint breach compromised 200 accounts

**Source:** BleepingComputer
**Published:** 2026-08-06
**Article:** https://www.bleepingcomputer.com/news/security/swiss-government-sharepoint-breach-compromised-200-accounts/

## Threat Profile

Swiss government SharePoint breach compromised 200 accounts 
By Lawrence Abrams 
August 6, 2026
02:14 PM
0 
Switzerland’s federal IT office says hackers exploited vulnerabilities to breach its Microsoft SharePoint servers and compromised approximately 200 accounts.
The Federal Office for Information Technology and Telecommunication (BIT) detected the cyberattack after security specialists noticed unusual activity on its SharePoint servers on July 28.
After confirming the breach, BIT blocked exte…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-56164`
- **CVE:** `CVE-2026-50522`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1059.003** — Windows Command Shell
- **T1552.004** — Private Keys
- **T1552.001** — Credentials In Files
- **T1505.003** — Web Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Anomalous POST to SharePoint ToolPane/_trust exploit endpoints (CVE-2026-50522/56164)

`UC_28_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method=POST (Web.url="*/_layouts/15/ToolPane.aspx*" OR Web.url="*/ToolPane.aspx*" OR Web.url="*/_trust/default.aspx*") by Web.src Web.dest Web.http_method Web.url Web.status Web.http_user_agent 
| `drop_dm_object_name(Web)` 
| where status<500 
| sort - lastTime
```

### SharePoint IIS worker (w3wp.exe) spawning command interpreter — ToolShell RCE

`UC_28_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=w3wp.exe (Processes.process_name=cmd.exe OR Processes.process_name=powershell.exe OR Processes.process_name=pwsh.exe OR Processes.process_name=mshta.exe OR Processes.process_name=cscript.exe OR Processes.process_name=wscript.exe OR Processes.process_name=rundll32.exe OR Processes.process_name=csc.exe OR Processes.process_name=certutil.exe) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path 
| `drop_dm_object_name(Processes)` 
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","mshta.exe","cscript.exe","wscript.exe","rundll32.exe","csc.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, InitiatingProcessIntegrityLevel, SHA256
| order by Timestamp desc
```

### SharePoint MachineKey / web.config credential theft via w3wp child process

`UC_28_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=w3wp.exe (Processes.process="*machineKey*" OR Processes.process="*ValidationKey*" OR Processes.process="*DecryptionKey*" OR Processes.process="*web.config*" OR Processes.process="*machine.config*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process 
| `drop_dm_object_name(Processes)` 
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wscript.exe")
| where ProcessCommandLine has_any ("machineKey","ValidationKey","DecryptionKey","web.config","machine.config")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Webshell/.aspx written into SharePoint LAYOUTS by w3wp.exe (ToolShell persistence)

`UC_28_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.aspx" OR Filesystem.file_name="*.ashx" by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name 
| `drop_dm_object_name(Filesystem)` 
| where process_name="w3wp.exe" AND (like(file_path,"%TEMPLATE\\LAYOUTS%") OR like(file_path,"%16\\TEMPLATE%") OR like(file_path,"%wwwroot%")) 
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName endswith ".aspx" or FileName endswith ".ashx"
| where FolderPath has_any (@"\TEMPLATE\LAYOUTS", @"\16\TEMPLATE", @"\web server extensions", @"\wwwroot")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-56164`, `CVE-2026-50522`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
