# [MED] MuddyWater: Snakes by the riverbank

**Source:** ESET WeLiveSecurity
**Published:** 2025-12-02
**Article:** https://www.welivesecurity.com/en/eset-research/muddywater-snakes-riverbank/

## Threat Profile

ESET researchers have identified new MuddyWater activity primarily targeting organizations in Israel, with one confirmed target in Egypt. MuddyWater, also referred to as Mango Sandstorm or TA450, is an Iran-aligned cyberespionage group known for its persistent targeting of government and critical infrastructure sectors, often leveraging custom malware and publicly available tools. In this campaign, the attackers deployed a set of previously undocumented, custom tools with the objective of improv…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1568** — Dynamic Resolution
- **T1555.003** — Credentials from Password Stores: Credentials from Web Browsers
- **T1003** — OS Credential Dumping
- **T1074.001** — Local Data Staged

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] MuddyWater Fooder/MuddyViper persistence — ManageOnDriveUpdater task or PPBCompatCache\ManagerCache install

`UC_266_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name=schtasks.exe AND Processes.process="*ManageOnDriveUpdater*") OR Processes.process="*ManageOnDriveUpdater*" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.process_name) as writer from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\Microsoft\\Windows\\PPBCompatCache\\ManagerCache*" by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)`] | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as data values(Registry.process_name) as writer from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Explorer\\User Shell Folders*" OR Registry.registry_path="*\\Explorer\\Shell Folders*") AND Registry.registry_value_name="Startup" AND Registry.registry_value_data="*PPBCompatCache*" by Registry.dest Registry.user | `drop_dm_object_name(Registry)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _persist_path = @"\Microsoft\Windows\PPBCompatCache\ManagerCache";
let _task_name = "ManageOnDriveUpdater";
union isfuzzy=true
    (DeviceProcessEvents
        | where Timestamp > ago(30d)
        | where AccountName !endswith "$"
        | where (FileName =~ "schtasks.exe" and ProcessCommandLine has _task_name)
             or ProcessCommandLine has _task_name
        | extend Signal = "schtasks/ManageOnDriveUpdater"
        | project Timestamp, Signal, DeviceName, AccountName, FileName, ProcessCommandLine,
                  ParentProcess = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
                  SHA256, ReportId),
    (DeviceFileEvents
        | where Timestamp > ago(30d)
        | where ActionType in ("FileCreated","FileModified","FileRenamed")
        | where FolderPath has _persist_path
        | extend Signal = "Write to PPBCompatCache\\ManagerCache"
        | project Timestamp, Signal, DeviceName, AccountName = InitiatingProcessAccountName,
                  FileName, FolderPath, SHA256,
                  WriterProcess = InitiatingProcessFileName,
                  WriterCmd = InitiatingProcessCommandLine, ReportId),
    (DeviceRegistryEvents
        | where Timestamp > ago(30d)
        | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
        | where RegistryKey has @"\Explorer\User Shell Folders"
             or RegistryKey has @"\Explorer\Shell Folders"
        | where RegistryValueName =~ "Startup"
        | where RegistryValueData has "PPBCompatCache" or RegistryValueData has "ManagerCache"
        | extend Signal = "Startup folder hijack to ManagerCache"
        | project Timestamp, Signal, DeviceName, AccountName = InitiatingProcessAccountName,
                  RegistryKey, RegistryValueName, RegistryValueData,
                  WriterProcess = InitiatingProcessFileName, ReportId)
| order by Timestamp desc
```

### [LLM] MuddyViper C2 — IOC infrastructure, WinHTTP-sample User-Agent and short-token URIs

`UC_266_1` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports values(All_Traffic.app) as proc from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("3.95.7.142","35.175.224.64","51.16.209.105","62.106.66.112","157.20.182.45","161.35.172.55","167.99.224.13","194.11.246.78","194.11.246.101","206.71.149.51","212.232.22.136") by All_Traffic.src All_Traffic.dest_ip | `drop_dm_object_name(All_Traffic)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as ua from datamodel=Web.Web where Web.url="*processplanet.org*" OR Web.url="*api.tikavodot.co.il*" OR Web.url="*magicallyday.com*" OR Web.url="*filter_relational_operator_2=*" OR Web.http_user_agent="A WinHTTP Example Program/1.0" OR Web.url IN ("*/adad*","*/aq36*","*/mq65*","*/oi32*","*/dadw*","*/dadwqa*","*/rq13*") by Web.src Web.dest | `drop_dm_object_name(Web)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _ips = dynamic(["3.95.7.142","35.175.224.64","51.16.209.105","62.106.66.112","157.20.182.45","161.35.172.55","167.99.224.13","194.11.246.78","194.11.246.101","206.71.149.51","212.232.22.136"]);
let _domains = dynamic(["processplanet.org","api.tikavodot.co.il","magicallyday.com"]);
let _uri_tokens = dynamic(["/adad","/aq36","/mq65","/oi32","/dadw","/dadwqa","/rq13"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt","HttpConnectionInspected")
| where RemoteIP in (_ips)
     or (isnotempty(RemoteUrl) and (
            RemoteUrl has_any (_domains)
         or RemoteUrl has "filter_relational_operator_2="
         or RemoteUrl has_any (_uri_tokens)))
| extend Signal = case(RemoteIP in (_ips), "IOC IP",
                       RemoteUrl has_any (_domains), "IOC domain",
                       RemoteUrl has "filter_relational_operator_2=", "MuddyViper URL param",
                       "MuddyViper short URI token")
| project Timestamp, Signal, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          RemoteIP, RemotePort, RemoteUrl, Protocol, ActionType, ReportId
| order by Timestamp desc
```

### [LLM] MuddyWater CE-Notes / LP-Notes credential dump artefacts in C:\Users\Public\Downloads

`UC_266_2` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as writer values(Filesystem.process_path) as writer_path from datamodel=Endpoint.Filesystem where Filesystem.file_path="C:\\Users\\Public\\Downloads\\*" AND (Filesystem.file_name="ce-notes.txt" OR Filesystem.file_name="lp-notes.txt" OR Filesystem.file_name="CacheDump.zip") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_name IN (powershell.exe,pwsh.exe) AND Processes.process="*Invoke-WebRequest*" AND (Processes.process="*ce-notes*" OR Processes.process="*lp-notes*") by Processes.dest Processes.user | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _drop_dir = @"C:\Users\Public\Downloads\";
let _stealer_outputs = dynamic(["ce-notes.txt","lp-notes.txt","CacheDump.zip"]);
union isfuzzy=true
    (DeviceFileEvents
        | where Timestamp > ago(30d)
        | where ActionType in ("FileCreated","FileModified","FileRenamed")
        | where FolderPath startswith _drop_dir
        | where FileName in~ (_stealer_outputs)
        | extend Signal = strcat("CE/LP-Notes drop: ", FileName)
        | project Timestamp, Signal, DeviceName,
                  AccountName = InitiatingProcessAccountName,
                  FileName, FolderPath, SHA256,
                  WriterProcess = InitiatingProcessFileName,
                  WriterCmd = InitiatingProcessCommandLine,
                  ParentProcess = InitiatingProcessParentFileName, ReportId),
    (DeviceProcessEvents
        | where Timestamp > ago(30d)
        | where FileName in~ ("powershell.exe","pwsh.exe")
        | where ProcessCommandLine has "Invoke-WebRequest"
        | where ProcessCommandLine has_any ("ce-notes","lp-notes")
        | extend Signal = "PowerShell Invoke-WebRequest fetching CE/LP-Notes"
        | project Timestamp, Signal, DeviceName, AccountName, FileName,
                  ProcessCommandLine, InitiatingProcessFileName,
                  InitiatingProcessCommandLine, ReportId)
| order by Timestamp desc
```


## Why this matters

Severity classified as **MED** based on: 3 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
