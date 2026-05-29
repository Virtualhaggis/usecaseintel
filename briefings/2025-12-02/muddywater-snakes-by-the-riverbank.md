# [MED] MuddyWater: Snakes by the riverbank

**Source:** ESET WeLiveSecurity
**Published:** 2025-12-02
**Article:** https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/

## Threat Profile

ESET researchers have identified new MuddyWater activity primarily targeting organizations in Israel, with one confirmed target in Egypt. MuddyWater, also referred to as Mango Sandstorm or TA450, is an Iran-aligned cyberespionage group known for its persistent targeting of government and critical infrastructure sectors, often leveraging custom malware and publicly available tools. In this campaign, the attackers deployed a set of previously undocumented, custom tools with the objective of improv…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1620** — Reflective Code Loading
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1112** — Modify Registry
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1132.001** — Data Encoding: Standard Encoding
- **T1041** — Exfiltration Over C2 Channel
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1074.001** — Data Staged: Local Data Staging
- **T1003.001** — OS Credential Dumping: LSASS Memory
- **T1140** — Deobfuscate/Decode Files or Information
- **T1134.001** — Access Token Manipulation: Token Impersonation/Theft

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] MuddyWater Fooder loader (OsUpdater.exe) execution from Downloads

`UC_641_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="OsUpdater.exe" AND Processes.process_path="*\\Downloads\\*") OR Processes.process_hash IN ("76632910CF67697BF5D7285FAE38BFCF438EC082","0657D0B0610618886DDD74C3D0A1D582CDD24863","2939FD218E0145D730BD94AA1C76386A5259EACE","1723D5EA7185D2E339FA9529D245DAA5D5C9A932","8E21DE54638A79D8489C59D958B23FE22E90944A","29CDA06701F9A9C0A6791775C3EB70F5B52BBEFF") by host Processes.user Processes.process_name Processes.process_path Processes.process_hash Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName =~ "OsUpdater.exe" and FolderPath has @"\Downloads\")
   or SHA1 in~ (
     "76632910CF67697BF5D7285FAE38BFCF438EC082",
     "0657D0B0610618886DDD74C3D0A1D582CDD24863",
     "2939FD218E0145D730BD94AA1C76386A5259EACE",
     "1723D5EA7185D2E339FA9529D245DAA5D5C9A932",
     "8E21DE54638A79D8489C59D958B23FE22E90944A",
     "29CDA06701F9A9C0A6791775C3EB70F5B52BBEFF"
   )
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA1,
          ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] MuddyViper persistence via ManageOnDriveUpdater scheduled task or Startup folder hijack

`UC_641_1` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
(`wineventlog_security` EventCode=4698 TaskName="*ManageOnDriveUpdater*") OR (| tstats summariesonly=true count from datamodel=Endpoint.Registry where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" AND Registry.registry_value_name="Startup" by host Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_guid | `drop_dm_object_name(Registry)` | where NOT match(registry_value_data, "(?i)\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup$"))
```

**Defender KQL:**
```kql
let SchedTaskHits =
    DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "ScheduledTaskCreated"
    | where AdditionalFields has "ManageOnDriveUpdater" or FileName has "ManageOnDriveUpdater"
    | project Timestamp, DeviceName, Signal = "SchedTask:ManageOnDriveUpdater",
              AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields;
let StartupHijackHits =
    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
         or RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
    | where RegistryValueName =~ "Startup"
    | where InitiatingProcessFileName !in~ ("explorer.exe","svchost.exe","msiexec.exe","setup.exe")
    | where not(RegistryValueData has_cs @"\Microsoft\Windows\Start Menu\Programs\Startup")
    | project Timestamp, DeviceName, Signal = "Reg:UserShellFolders.Startup",
              AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              AdditionalFields = strcat("key=", RegistryKey, " val=", RegistryValueName, " data=", RegistryValueData);
union SchedTaskHits, StartupHijackHits
| where AccountName !endswith "$"
| order by Timestamp desc
```

### [LLM] MuddyViper C2 fingerprint: 'A WinHTTP Example Program/1.0' UA + distinctive URI paths

`UC_641_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_user_agent="A WinHTTP Example Program/1.0") OR (Web.url IN ("*/adad","*/aq36","*/mq65","*/oi32","*/dadw","*/dadwqa","*/rq13")) OR (Web.dest IN ("processplanet.org","api.tikavodot.co.il","magicallyday.com","3.95.7.142","35.175.224.64","51.16.209.105","62.106.66.112","157.20.182.45","161.35.172.55","167.99.224.13","194.11.246.78","194.11.246.101","206.71.149.51","212.232.22.136")) by host Web.src Web.user Web.dest Web.url Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let MuddyViperIPs = dynamic(["3.95.7.142","35.175.224.64","51.16.209.105","62.106.66.112","157.20.182.45","161.35.172.55","167.99.224.13","194.11.246.78","194.11.246.101","206.71.149.51","212.232.22.136"]);
let MuddyViperDomains = dynamic(["processplanet.org","api.tikavodot.co.il","magicallyday.com"]);
let MuddyViperUriTokens = dynamic(["/adad","/aq36","/mq65","/oi32","/dadw","/dadwqa","/rq13"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected","ConnectionAttempt")
| where RemoteIP in (MuddyViperIPs)
   or RemoteUrl has_any (MuddyViperDomains)
   or RemoteUrl has_any (MuddyViperUriTokens)
   or AdditionalFields has_cs "A WinHTTP Example Program/1.0"
| where InitiatingProcessFileName !in~ ("msedge.exe","chrome.exe","firefox.exe","iexplore.exe")
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName,
          RemoteIP, RemotePort, RemoteUrl, AdditionalFields
| order by Timestamp desc
```

### [LLM] MuddyWater CE-Notes / LP-Notes / Blub stealer staging-file writes

`UC_641_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="C:\\Users\\Public\\Downloads\\ce-notes.txt" OR Filesystem.file_path="C:\\Users\\Public\\Downloads\\lp-notes.txt" OR Filesystem.file_path="C:\\Users\\Public\\Downloads\\system2.dll" OR Filesystem.file_path="C:\\system2.dll" OR Filesystem.file_path="C:\\Intel\\system.dll") AND Filesystem.action="created" by host Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where (FolderPath =~ @"C:\Users\Public\Downloads" and FileName in~ ("ce-notes.txt","lp-notes.txt","system2.dll"))
   or (FolderPath =~ @"C:\" and FileName =~ "system2.dll")
   or (FolderPath =~ @"C:\Intel" and FileName =~ "system.dll")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ ("msmpeng.exe","mssense.exe","sense.exe","explorer.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA1, SHA256
| order by Timestamp desc
```

### [LLM] Non-browser process reading Chrome/Edge/Opera Login Data or Local State

`UC_641_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*\\Google\\Chrome\\User Data\\Local State","*\\Google\\Chrome\\User Data\\*\\Login Data","*\\Microsoft\\Edge\\User Data\\Local State","*\\Microsoft\\Edge\\User Data\\*\\Login Data","*\\Opera Software\\Opera Stable\\Local State","*\\Mozilla\\Firefox\\Profiles\\*\\logins.json","*\\Mozilla\\Firefox\\Profiles\\*\\key4.db")) AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","opera.exe","firefox.exe","brave.exe","vivaldi.exe","MsMpEng.exe","MsSense.exe") by host Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated" or ActionType == "FileOpened" or ActionType == "FileRenamed"
| where (FolderPath has @"\Google\Chrome\User Data" and (FileName =~ "Local State" or FileName =~ "Login Data"))
     or (FolderPath has @"\Microsoft\Edge\User Data" and (FileName =~ "Local State" or FileName =~ "Login Data"))
     or (FolderPath has @"\Opera Software\Opera Stable" and FileName =~ "Local State")
     or (FolderPath has @"\Mozilla\Firefox\Profiles" and FileName in~ ("logins.json","key4.db"))
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","opera.exe","firefox.exe","brave.exe","vivaldi.exe","msmpeng.exe","mssense.exe","sense.exe","explorer.exe")
| where InitiatingProcessAccountName !endswith "$"
| extend Suspicious =
      case(InitiatingProcessFileName =~ "taskhostw.exe" and InitiatingProcessFolderPath !startswith @"C:\Windows\System32", "LP-Notes_taskhostw_impersonation",
           InitiatingProcessFolderPath has @"\Users\Public\Downloads\", "PublicDownloads_stealer",
           "non-browser-secret-read")
| project Timestamp, DeviceName, InitiatingProcessAccountName, Suspicious,
          FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessSHA1
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 5 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
