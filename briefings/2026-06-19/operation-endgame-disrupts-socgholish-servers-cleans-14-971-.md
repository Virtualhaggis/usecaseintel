# [CRIT] Operation Endgame Disrupts SocGholish Servers, Cleans 14,971 WordPress Sites

**Source:** The Hacker News
**Published:** 2026-06-19
**Article:** https://thehackernews.com/2026/06/operation-endgame-disrupts-socgholish.html

## Threat Profile

Operation Endgame Disrupts SocGholish Servers, Cleans 14,971 WordPress Sites 
 Ravie Lakshmanan  Jun 19, 2026 Malware / Threat Intelligence 
Dutch law enforcement authorities, along with counterparts from Canada , Germany, and the U.S., have disrupted malicious infrastructure associated with SocGholish and cleaned up nearly 15,000 infected WordPress websites.
"With these actions we deprive cybercriminals of access to infected computer systems," Maikel Rollman of the Netherlands National High T…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1189** — Drive-by Compromise
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1219** — Remote Access Software
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SocGholish fake browser-update JavaScript executed by Windows Script Host from a download path

`UC_102_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("wscript.exe","cscript.exe")) AND (Processes.parent_process_name IN ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","winrar.exe","7zFM.exe","7zG.exe")) AND (Processes.process="*.js*") AND (Processes.process IN ("*\\Downloads\\*","*\\Temp\\*","*\\AppData\\*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ('wscript.exe','cscript.exe')
| where ProcessCommandLine has '.js'
| where ProcessCommandLine has_any (@'\Downloads\', @'\Temp\', @'\AppData\')
| where InitiatingProcessFileName in~ ('explorer.exe','chrome.exe','msedge.exe','firefox.exe','brave.exe','opera.exe','winrar.exe','7zFM.exe','7zG.exe')
| where AccountName !endswith '$'
| project Timestamp, DeviceName, AccountName, ParentProcess=InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### SocGholish second stage: Windows Script Host spawning PowerShell

`UC_102_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("wscript.exe","cscript.exe")) AND (Processes.process_name IN ("powershell.exe","pwsh.exe")) AND (Processes.parent_process="*.js*") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ('wscript.exe','cscript.exe')
| where FileName in~ ('powershell.exe','pwsh.exe')
| where InitiatingProcessCommandLine has '.js'
| where AccountName !endswith '$'
| project Timestamp, DeviceName, AccountName, ParentCmd=InitiatingProcessCommandLine, ChildCmd=ProcessCommandLine, SHA256
| order by Timestamp desc
```

### SocGholish-delivered NetSupport RAT (client32.exe) executing from a non-standard directory

`UC_102_6` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="client32.exe" OR Processes.original_file_name="client32.exe") AND (Processes.process_path IN ("*\\ProgramData\\*","*\\Users\\Public\\*","*\\AppData\\*","*\\Windows\\Temp\\*","*\\Downloads\\*")) by Processes.dest Processes.user Processes.process_name Processes.original_file_name Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ 'client32.exe' or ProcessVersionInfoOriginalFileName =~ 'client32.exe' or ProcessVersionInfoProductName has 'NetSupport'
| where FolderPath has_any (@'\ProgramData\', @'\Users\Public\', @'\AppData\', @'\Windows\Temp\', @'\Downloads\')
| where AccountName !endswith '$'
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, ProcessVersionInfoOriginalFileName, ProcessVersionInfoProductName
| order by Timestamp desc
```

### SocGholish/NetSupport Run-key persistence pointing to a user-writable executable

`UC_102_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentVersion\\Run*") AND (Registry.registry_value_data IN ("*\\ProgramData\\*","*\\Users\\Public\\*","*\\AppData\\Roaming\\*","*\\AppData\\Local\\*","*\\Windows\\Temp\\*")) AND (Registry.registry_value_data="*.exe*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where ActionType == 'RegistryValueSet'
| where RegistryKey has @'\CurrentVersion\Run'
| where RegistryValueData has_any (@'\ProgramData\', @'\Users\Public\', @'\AppData\Roaming\', @'\AppData\Local\', @'\Windows\Temp\')
| where RegistryValueData has '.exe'
| where InitiatingProcessAccountName !endswith '$'
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
