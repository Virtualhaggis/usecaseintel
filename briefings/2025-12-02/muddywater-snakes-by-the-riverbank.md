# [MED] MuddyWater: Snakes by the riverbank

**Source:** ESET WeLiveSecurity
**Published:** 2025-12-02
**Article:** https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/

## Threat Profile

ESET researchers have identified new MuddyWater activity primarily targeting organizations in Israel, with one confirmed target in Egypt. MuddyWater, also referred to as Mango Sandstorm or TA450, is an Iran-aligned cyberespionage group known for its persistent targeting of government and critical infrastructure sectors, often leveraging custom malware and publicly available tools. In this campaign, the attackers deployed a set of previously undocumented, custom tools with the objective of improv…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1573.001** — Encrypted Channel: Symmetric Cryptography
- **T1041** — Exfiltration Over C2 Channel
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer
- **T1140** — Deobfuscate/Decode Files or Information
- **T1547.001** — Boot or Logon Autostart: Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1555.003** — Credentials from Web Browsers
- **T1056.002** — GUI Input Capture

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] MuddyViper HTTP C2 beacon: WinHTTP example UA + distinctive URI paths on port 443

`UC_271_0` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_user_agent="A WinHTTP Example Program/1.0" OR Web.url_path IN ("/adad","/aq36","/mq65","/oi32","/dadw","/dadwqa","/rq13") OR Web.dest IN ("processplanet.org","api.tikavodot.co.il","magicallyday.com","3.95.7.142","35.175.224.64","51.16.209.105","62.106.66.112","157.20.182.45","161.35.172.55","167.99.224.13","194.11.246.78","194.11.246.101","206.71.149.51","212.232.22.136")) by Web.src Web.dest Web.dest_port Web.url Web.url_path Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | where http_user_agent="A WinHTTP Example Program/1.0" OR (url_path IN ("/adad","/aq36","/mq65","/oi32","/dadw","/dadwqa","/rq13") AND dest_port IN (80,443)) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let muddyUris = dynamic(["/adad","/aq36","/mq65","/oi32","/dadw","/dadwqa","/rq13"]);
let muddyIps = dynamic(["3.95.7.142","35.175.224.64","51.16.209.105","62.106.66.112","157.20.182.45","161.35.172.55","167.99.224.13","194.11.246.78","194.11.246.101","206.71.149.51","212.232.22.136"]);
let muddyDomains = dynamic(["processplanet.org","api.tikavodot.co.il","magicallyday.com"]);
DeviceNetworkEvents
| where Timestamp > ago(45d)
| where RemotePort in (80,443)
| extend Path = tostring(parse_url(RemoteUrl).Path)
| where Path in (muddyUris) or RemoteIP in (muddyIps) or RemoteUrl has_any (muddyDomains)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","opera.exe","brave.exe","outlook.exe","teams.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemotePort, RemoteUrl, Path, ActionType
```

### [LLM] MuddyWater PowerShell IEX stager with 'filter_relational_operator_2' query parameter

`UC_271_1` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="powershell.exe" AND Processes.process="*Invoke-WebRequest*" AND Processes.process="*Invoke-Expression*" AND (Processes.process="*filter_relational_operator_2*" OR (Processes.process="*-UseDefaultCredentials*" AND Processes.process="*-UseBasicParsing*" AND Processes.process="*:443/*?*")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process Processes.process_id | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(45d)
| where FileName =~ "powershell.exe" or ProcessCommandLine has_any ("powershell","pwsh")
| where ProcessCommandLine has "Invoke-WebRequest" and ProcessCommandLine has "Invoke-Expression"
| where ProcessCommandLine has "filter_relational_operator_2"
   or (ProcessCommandLine has "-UseDefaultCredentials" and ProcessCommandLine has "-UseBasicParsing" and ProcessCommandLine matches regex @"https?://[^\s\"']+:443/\d+\?")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

### [LLM] MuddyViper / CE-Notes / LP-Notes staging files and ManagerCache startup persistence

`UC_271_2` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("ce-notes.txt","lp-notes.txt") AND Filesystem.file_path="*\\Users\\Public\\Downloads\\*") OR Filesystem.file_path="*\\Microsoft\\Windows\\PPBCompatCache\\ManagerCache*" OR Filesystem.file_path="*\\Users\\Public\\Downloads\\system2.dll" OR Filesystem.file_path="C:\\Intel\\system.dll" OR Filesystem.file_path="C:\\system2.dll" by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | append [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name IN ("schtasks.exe","powershell.exe") AND (Processes.process="*ManageOnDriveUpdater*" OR Processes.process="*PPBCompatCache\\ManagerCache*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` ] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let staging =
  DeviceFileEvents
  | where Timestamp > ago(60d)
  | where (FileName in~ ("ce-notes.txt","lp-notes.txt") and FolderPath has @"\Users\Public\Downloads\")
     or FolderPath has @"\Microsoft\Windows\PPBCompatCache\ManagerCache"
     or FolderPath endswith @"\Users\Public\Downloads\system2.dll"
     or FolderPath =~ @"C:\Intel\system.dll"
     or FolderPath =~ @"C:\system2.dll"
  | project Timestamp, DeviceName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA1=InitiatingProcessSHA1;
let persistence =
  DeviceProcessEvents
  | where Timestamp > ago(60d)
  | where (FileName =~ "schtasks.exe" and ProcessCommandLine has "ManageOnDriveUpdater")
     or ProcessCommandLine has @"PPBCompatCache\ManagerCache"
  | project Timestamp, DeviceName, ActionType="ProcessExec", FileName, FolderPath="", InitiatingProcessFileName, InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessFolderPath=FolderPath, SHA1;
let regPersist =
  DeviceRegistryEvents
  | where Timestamp > ago(60d)
  | where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
     or RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
  | where RegistryValueName =~ "Startup" and RegistryValueData has @"PPBCompatCache\ManagerCache"
  | project Timestamp, DeviceName, ActionType=ActionType, FileName="", FolderPath=RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA1=InitiatingProcessSHA1;
union staging, persistence, regPersist
| sort by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 3 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
