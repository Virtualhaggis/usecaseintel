# [HIGH] Malicious RVTools Installer Abuses Sectigo Certificate to Bypass SmartScreen Warnings

**Source:** Cyber Security News
**Published:** 2026-05-29
**Article:** https://cybersecuritynews.com/malicious-rvtools-installer-abuses-sectigo-certificate/

## Threat Profile

Home Cyber Security News 
Malicious RVTools Installer Abuses Sectigo Certificate to Bypass SmartScreen Warnings 
By Tushar Subhra Dutta 
May 29, 2026 
A trusted tool for VMware administrators has been weaponized. Attackers built a fake version of RVTools, a widely used utility for managing virtual infrastructure, and disguised it with a real digital certificate to slip past Windows security warnings without raising a flag. 
RVTools is a staple in enterprise environments. IT administrators rely o…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `d0f5e98fb840fb5656d3f50613b6f1ec60e57392643159841bc1fa95396087a4`
- **MD5:** `64bda120cb447e0c03f451190022a57b`
- **MD5:** `01a115c6f6ba3837234202a1e0d28bdc`
- **MD5:** `71085940124ad3c035a181acadc10362`
- **MD5:** `9192d18a955a9d03e2c70b60aac1784a`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1588.003** — Code Signing Certificates
- **T1036.001** — Invalid Code Signature
- **T1204.002** — User Execution: Malicious File
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1059.005** — Visual Basic
- **T1140** — Deobfuscate/Decode Files or Information
- **T1105** — Ingress Tool Transfer
- **T1102** — Web Service
- **T1059.006** — Python
- **T1071.001** — Application Layer Protocol: Web
- **T1041** — Exfiltration Over C2 Channel
- **T1082** — System Information Discovery
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Malicious RVTools MSI signed by Xiamen Lunwei Huage (Sectigo) — hash + cert subject

`UC_3_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_hash IN ("d0f5e98fb840fb5656d3f50613b6f1ec60e57392643159841bc1fa95396087a4","64bda120cb447e0c03f451190022a57b") OR Filesystem.file_name="RVTools*.msi") by host Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
union
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 == "d0f5e98fb840fb5656d3f50613b6f1ec60e57392643159841bc1fa95396087a4"
        or MD5 in~ ("64bda120cb447e0c03f451190022a57b","01a115c6f6ba3837234202a1e0d28bdc","71085940124ad3c035a181acadc10362","9192d18a955a9d03e2c70b60aac1784a")
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, MD5, InitiatingProcessFileName, InitiatingProcessCommandLine, FileOriginUrl),
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where (FileName =~ "msiexec.exe" and ProcessCommandLine has_any ("RVTools","rvtools"))
        or SHA256 == "d0f5e98fb840fb5656d3f50613b6f1ec60e57392643159841bc1fa95396087a4"
        or InitiatingProcessVersionInfoCompanyName has "Xiamen Lunwei Huage"
        or ProcessVersionInfoCompanyName has "Xiamen Lunwei Huage"
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, SHA256, ProcessVersionInfoCompanyName, InitiatingProcessFileName)
| order by Timestamp desc
```

### [LLM] msiexec spawning wscript Binary.MyScript.vbs → hidden powershell (RVTools chain)

`UC_3_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.parent_process_name="msiexec.exe" Processes.process_name IN ("wscript.exe","cscript.exe") (Processes.process="*Binary.MyScript.vbs*" OR Processes.process="*MyScript.vbs*") by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let VbsExec = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "msiexec.exe"
    | where FileName in~ ("wscript.exe","cscript.exe")
    | where ProcessCommandLine has_any ("Binary.MyScript.vbs","MyScript.vbs")
    | project VbsTime=Timestamp, DeviceId, VbsPid=ProcessId, VbsCmd=ProcessCommandLine, DeviceName, AccountName;
let PsChild = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
    | where FileName in~ ("powershell.exe","pwsh.exe")
    | where ProcessCommandLine has_any ("-w hidden","-WindowStyle Hidden","-WindowStyle h","-nop","-noprofile","DownloadFile","Invoke-WebRequest","iwr ","dropbox")
        or ProcessCommandLine matches regex @"\[char\]\d{2,3}"
    | project PsTime=Timestamp, DeviceId, VbsPid=InitiatingProcessId, PsCmd=ProcessCommandLine;
VbsExec
| join kind=inner PsChild on DeviceId, VbsPid
| where PsTime between (VbsTime .. VbsTime + 5m)
| project VbsTime, DeviceName, AccountName, VbsCmd, PsTime, PsCmd
```

### [LLM] PowerShell download of winp.zip ~33MB from Dropbox into %APPDATA%

`UC_3_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.file_size) as size from datamodel=Endpoint.Filesystem where Filesystem.file_name="winp.zip" Filesystem.file_path IN ("*\\AppData\\*","*\\Users\\*\\AppData\\*") by host Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let DropboxDownload = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
    | where RemoteUrl has_any ("dropbox.com","dl.dropboxusercontent.com","www.dropbox.com")
    | project NetTime=Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessId, InitiatingProcessCommandLine, RemoteUrl, RemoteIP;
let ZipDrop = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "winp.zip" or FileName matches regex @"(?i)^winp.*\.zip$"
    | where FolderPath has @"\AppData\"
    | project FileTime=Timestamp, DeviceId, FileName, FolderPath, FileSize, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCommandLine;
union DropboxDownload, ZipDrop
| summarize NetEvents=countif(isnotempty(RemoteUrl)), FileEvents=countif(isnotempty(FileName)),
            arg_max(NetTime, RemoteUrl), arg_max(FileTime, FolderPath, FileSize)
            by DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessId
| where NetEvents > 0 and FileEvents > 0
```

### [LLM] Portable python.exe launching from AppData running Pmanager.py / collector.py

`UC_3_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="python.exe" Processes.process_path IN ("*\\AppData\\*") (Processes.process="*Pmanager.py*" OR Processes.process="*collector.py*" OR Processes.process="*configA.json*") by host Processes.user | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let PyExec = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "python.exe" or FileName =~ "pythonw.exe"
    | where FolderPath has @"\AppData\"
    | where ProcessCommandLine has_any ("Pmanager.py","collector.py","configA.json")
    | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, ProcessId, InitiatingProcessFileName, InitiatingProcessCommandLine;
let Beacons = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("python.exe","pythonw.exe")
    | where InitiatingProcessFolderPath has @"\AppData\"
    | where RemoteIPType == "Public"
    | summarize Connections=count(), DistinctRemotes=dcount(RemoteIP), FirstBeacon=min(Timestamp), LastBeacon=max(Timestamp)
              by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessFolderPath
    | where Connections >= 3 and (datetime_diff('second', LastBeacon, FirstBeacon) / Connections) between (240 .. 360);
PyExec
| union Beacons
| order by Timestamp desc
```

### [LLM] RVTools RAT persistence: Run key + SYSTEM scheduled task pointing to AppData python

`UC_3_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Registry.registry_value_data) as value_data values(Registry.process_name) as writer from datamodel=Endpoint.Registry where (Registry.registry_path="*\\Microsoft\\Windows\\CurrentVersion\\Run\\*" OR Registry.registry_path="*\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*") (Registry.registry_value_data="*\\AppData\\*python*" OR Registry.registry_value_data="*Pmanager.py*" OR Registry.registry_value_data="*collector.py*") by host Registry.registry_value_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let RunKey = DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("RegistryValueSet","RegistryKeyCreated")
    | where RegistryKey has_any (@"\Microsoft\Windows\CurrentVersion\Run", @"\Microsoft\Windows\CurrentVersion\RunOnce")
    | where RegistryValueData has_any (@"\AppData\", "Pmanager.py", "collector.py")
    | where RegistryValueData has_any ("python.exe","pythonw.exe","Pmanager.py","collector.py")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine;
let SchedTask = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("ScheduledTaskCreated","ScheduledTaskUpdated")
    | where AdditionalFields has_any ("Pmanager.py","collector.py")
        or (AdditionalFields has @"\AppData\" and AdditionalFields has_any ("python.exe","pythonw.exe"))
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, ActionType, AdditionalFields, InitiatingProcessFileName;
union RunKey, SchedTask
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
```

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — Malicious RVTools Installer Abuses Sectigo Certificate to Bypass SmartScreen War

`UC_3_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Malicious RVTools Installer Abuses Sectigo Certificate to Bypass SmartScreen War ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("collector.py","pmanager.py","binary.myscript.vbs"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("collector.py","pmanager.py","binary.myscript.vbs"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Malicious RVTools Installer Abuses Sectigo Certificate to Bypass SmartScreen War
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("collector.py", "pmanager.py", "binary.myscript.vbs"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("collector.py", "pmanager.py", "binary.myscript.vbs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `d0f5e98fb840fb5656d3f50613b6f1ec60e57392643159841bc1fa95396087a4`, `64bda120cb447e0c03f451190022a57b`, `01a115c6f6ba3837234202a1e0d28bdc`, `71085940124ad3c035a181acadc10362`, `9192d18a955a9d03e2c70b60aac1784a`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
