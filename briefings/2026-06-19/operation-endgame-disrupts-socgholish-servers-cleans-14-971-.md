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
- **T1105** — Ingress Tool Transfer
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1547.001** — Registry Run Keys / Startup Folder

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SocGholish fake-update JS dropped to Downloads by a web browser

`UC_7_4` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe") Filesystem.file_path="*\\Downloads\\*" Filesystem.file_name="*.js" (Filesystem.file_name="*update*" OR Filesystem.file_name="*chrome*" OR Filesystem.file_name="*firefox*" OR Filesystem.file_name="*opera*" OR Filesystem.file_name="*browser*") by host Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","arc.exe")
| where FolderPath has @"\Downloads\"
| where FileName endswith ".js"
| where FileName has_any ("update","chrome","firefox","opera","browser")
| where FileName !endswith ".js.map"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, SHA256
| order by Timestamp desc
```

### SocGholish JS stager: wscript.exe executing .js from Downloads with browser/explorer parent

`UC_7_5` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="wscript.exe" Processes.parent_process_name IN ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe") (Processes.process="*\\Downloads\\*.js*" OR Processes.process="*\\Users\\*\\AppData\\Local\\Temp\\*.js*") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "wscript.exe"
| where InitiatingProcessFileName in~ ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| where ProcessCommandLine has ".js"
| where ProcessCommandLine has_any (@"\Downloads\", @"\AppData\Local\Temp\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### SocGholish PowerShell second stage: wscript spawning PowerShell with Invoke-WebRequest to .svg payload

`UC_7_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") Processes.parent_process_name IN ("wscript.exe","cscript.exe") (Processes.process="*Invoke-WebRequest*" OR Processes.process="*IWR *" OR Processes.process="*iex*" OR Processes.process="*Invoke-Expression*") Processes.process="*.svg*" by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any ("Invoke-WebRequest","iwr ","IEX","Invoke-Expression")
| where ProcessCommandLine has ".svg"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildCmd = ProcessCommandLine,
          Grandparent = InitiatingProcessParentFileName
| order by Timestamp desc
```

### NetSupport RAT client32.exe executing from AppData Roaming subfolder (SocGholish follow-on)

`UC_7_7` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="client32.exe" (Processes.process_path="*\\AppData\\Roaming\\*" OR Processes.process_path="*\\AppData\\Local\\*" OR Processes.process_path="*\\ProgramData\\*") Processes.process_path!="*\\Program Files*" by host Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "client32.exe"
| where FolderPath has_any (@"\AppData\Roaming\", @"\AppData\Local\", @"\ProgramData\", @"\Users\Public\")
| where FolderPath !has @"\Program Files"
| where InitiatingProcessVersionInfoCompanyName !has "NetSupport"
   or isempty(ProcessVersionInfoCompanyName)
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Path = FolderPath,
          ChildCmd = ProcessCommandLine,
          ProcessVersionInfoCompanyName,
          SHA256
| order by Timestamp desc
```

### NetSupport RAT Run-key persistence pointing to client32.exe in AppData

`UC_7_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.action=modified Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" (Registry.registry_value_data="*\\AppData\\Roaming\\*client32.exe*" OR Registry.registry_value_data="*\\AppData\\Local\\*client32.exe*") by host Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryValueCreated")
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueData has "client32.exe"
| where RegistryValueData has_any (@"\AppData\Roaming\", @"\AppData\Local\", @"\ProgramData\")
| where RegistryValueData !has @"\Program Files"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RegistryKey, RegistryValueName, RegistryValueData
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

Severity classified as **CRIT** based on: 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
