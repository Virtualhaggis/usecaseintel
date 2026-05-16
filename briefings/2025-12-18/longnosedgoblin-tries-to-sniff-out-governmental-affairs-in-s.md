# [CRIT] LongNosedGoblin tries to sniff out governmental affairs in Southeast Asia and Japan

**Source:** ESET WeLiveSecurity
**Published:** 2025-12-18
**Article:** https://www.welivesecurity.com/en/eset-research/longnosedgoblin-tries-sniff-out-governmental-affairs-southeast-asia-japan/

## Threat Profile

LongNosedGoblin tries to sniff out governmental affairs in Southeast Asia and Japan 
ESET Research
LongNosedGoblin tries to sniff out governmental affairs in Southeast Asia and Japan ESET researchers discovered a China-aligned APT group, LongNosedGoblin, which uses Group Policy to deploy cyberespionage tools across networks of governmental institutions
Anton Cherepanov 
Peter Strýček 
18 Dec 2025 
 •  
, 
24 min. read 
In 2024, ESET researchers noticed previously undocumented malware in the netw…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `118.107.234.29`
- **IPv4 (defanged):** `118.107.234.26`
- **IPv4 (defanged):** `103.159.132.30`
- **IPv4 (defanged):** `101.99.88.113`
- **IPv4 (defanged):** `101.99.88.188`
- **IPv4 (defanged):** `38.54.17.131`
- **Domain (defanged):** `server.com`
- **Domain (defanged):** `stub.com`
- **Domain (defanged):** `newso.com`
- **Domain (defanged):** `policy-my.com`
- **SHA256:** `D53FCC01038E20193FBD51B7400075CF7C9C4402B73DA7B0DB836B000EBD8B1C`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1574.014** — Hijack Execution Flow: AppDomainManager
- **T1218** — System Binary Proxy Execution
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1053.005** — Scheduled Task/Job: Scheduled Task

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] NosyDoor AppDomainManager hijack: UevAppMonitor.exe executing from non-standard path

`UC_518_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE Processes.process_name="UevAppMonitor.exe" AND Processes.process_path!="*\\Windows\\System32\\*" AND Processes.process_path!="*\\Windows\\SysWOW64\\*" BY Processes.dest Processes.user Processes.process_name Processes.process Processes.process_path Processes.parent_process_name Processes.parent_process Processes.process_hash | `drop_dm_object_name(Processes)` | eval suspicious_path=if(match(process_path,"(?i)\\\\Microsoft\\.NET\\\\Framework(64)?\\\\"),"yes","no") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// LongNosedGoblin NosyDoor stage-2 — UevAppMonitor.exe is a legitimate Windows binary that *only* ships in System32. Execution from anywhere else (especially Microsoft.NET\Framework) means a copy was staged by the dropper to side-load SharedReg.dll via AppDomainManager.
let UevExec =
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "UevAppMonitor.exe"
    | where not(FolderPath startswith @"C:\Windows\System32\")
    | where not(FolderPath startswith @"C:\Windows\SysWOW64\")
    | project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, SHA256;
let SharedRegLoad =
    DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "UevAppMonitor.exe"
    | where FileName =~ "SharedReg.dll"
    | where not(FolderPath startswith @"C:\Windows\WinSxS\")
    | project Timestamp, DeviceName, FolderPath, FileName, SHA256,
              InitiatingProcessFolderPath;
UevExec
| union SharedRegLoad
| order by Timestamp desc
```

### [LLM] NosyDoor persistence: scheduled task 'OneDrive Reporting Task-S-1-5-21-' under Microsoft folder

`UC_518_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem WHERE Filesystem.file_path="*\\Windows\\System32\\Tasks\\Microsoft\\OneDrive Reporting Task-S-1-5-21-*" BY Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// LongNosedGoblin NosyDoor persistence — scheduled task with literal prefix "OneDrive Reporting Task-S-1-5-21-" registered under \Microsoft\ task folder.
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileRenamed")
| where FolderPath has @"\Windows\System32\Tasks\Microsoft\"
| where FileName startswith "OneDrive Reporting Task-S-1-5-21-"
| project Timestamp, DeviceName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          InitiatingProcessAccountSid, SHA256
| order by Timestamp desc
```

### [LLM] NosyDoor dropper file artefacts in C:\Windows\Microsoft.NET\Framework

`UC_518_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files_seen FROM datamodel=Endpoint.Filesystem WHERE (Filesystem.file_path="*\\Windows\\Microsoft.NET\\Framework\\*" OR Filesystem.file_path="*\\Windows\\Microsoft.NET\\Framework64\\*") AND (Filesystem.file_name="SharedReg.dll" OR Filesystem.file_name="log.cached" OR Filesystem.file_name="netfxsbs9.hkf" OR Filesystem.file_name="UevAppMonitor.exe.config" OR Filesystem.file_name="UevAppMonitor.exe" OR Filesystem.file_name="error.txt") BY Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path | `drop_dm_object_name(Filesystem)` | where mvcount(files_seen) >= 2 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// LongNosedGoblin NosyDoor dropper — writes a known set of artefacts into C:\Windows\Microsoft.NET\Framework so the relocated UevAppMonitor.exe loads SharedReg.dll via .config-driven AppDomainManager injection.
let NosyDoorFiles = dynamic([
    "SharedReg.dll",
    "log.cached",
    "netfxsbs9.hkf",            // typo of legitimate netfxsbs12.hkf
    "UevAppMonitor.exe.config",
    "UevAppMonitor.exe",         // staged copy from System32
    "error.txt"                  // dropped on stage-2 decryption errors
]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath in~ (@"C:\Windows\Microsoft.NET\Framework", @"C:\Windows\Microsoft.NET\Framework64")
   or FolderPath endswith @"\Microsoft.NET\Framework"
   or FolderPath endswith @"\Microsoft.NET\Framework64"
| where FileName in~ (NosyDoorFiles)
// Exclude legitimate .NET servicing — the genuine SharedReg DLL is named SharedReg12.dll, not SharedReg.dll
| where not(InitiatingProcessFileName in~ ("TrustedInstaller.exe", "msiexec.exe", "setup.exe") and InitiatingProcessFolderPath startswith @"C:\Windows\")
| summarize FileSet = make_set(FileName), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Writers = make_set(InitiatingProcessFileName)
  by DeviceName, FolderPath, InitiatingProcessAccountName
| where array_length(FileSet) >= 2     // at least two of the four sibling artefacts
| order by LastSeen desc
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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

### Article-specific behavioural hunt — LongNosedGoblin tries to sniff out governmental affairs in Southeast Asia and Ja

`UC_518_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — LongNosedGoblin tries to sniff out governmental affairs in Southeast Asia and Ja ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("oci.dll","mscorsvc.dll","sharedreg.dll","uevappmonitor.exe","sharedreg12.dll","pmp.exe","serv.dll","msi.dll","amsi.dll","tcoedge.exe","rtlwvern.exe","hpsmartadapter.exe","hputils.exe","igccsvc.exe","adobehelper.exe") OR Processes.process="*Invoke-Expression*" OR Processes.process_path="*E:\Csharp\SharpMisc\GetBrowserHistory\obj\Debug\GetBrowserHistory.pdb*" OR Processes.process_path="*C:\Windows\Microsoft.NET\Framework*" OR Processes.process_path="*E:\Csharp\Thomas\Server\ThomasOneDrive\obj\Release\OneDrive.pdb*" OR Processes.process_path="*C:\Users\Public\Libraries\thomas.log*" OR Processes.process_path="*C:\ProgramData\Microsoft\WDF\MDE.dat*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*E:\Csharp\SharpMisc\GetBrowserHistory\obj\Debug\GetBrowserHistory.pdb*" OR Filesystem.file_path="*C:\Windows\Microsoft.NET\Framework*" OR Filesystem.file_path="*E:\Csharp\Thomas\Server\ThomasOneDrive\obj\Release\OneDrive.pdb*" OR Filesystem.file_path="*C:\Users\Public\Libraries\thomas.log*" OR Filesystem.file_path="*C:\ProgramData\Microsoft\WDF\MDE.dat*" OR Filesystem.file_path="*C:\ProgramData\Microsoft\WDF\pmp.exe*" OR Filesystem.file_path="*C:\ProgramData\Microsoft\WDF\mfd.dat*" OR Filesystem.file_path="*C:\Windows\Temp\TS_D418.tmp*" OR Filesystem.file_name IN ("oci.dll","mscorsvc.dll","sharedreg.dll","uevappmonitor.exe","sharedreg12.dll","pmp.exe","serv.dll","msi.dll","amsi.dll","tcoedge.exe","rtlwvern.exe","hpsmartadapter.exe","hputils.exe","igccsvc.exe","adobehelper.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — LongNosedGoblin tries to sniff out governmental affairs in Southeast Asia and Ja
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("oci.dll", "mscorsvc.dll", "sharedreg.dll", "uevappmonitor.exe", "sharedreg12.dll", "pmp.exe", "serv.dll", "msi.dll", "amsi.dll", "tcoedge.exe", "rtlwvern.exe", "hpsmartadapter.exe", "hputils.exe", "igccsvc.exe", "adobehelper.exe") or ProcessCommandLine has_any ("Invoke-Expression") or FolderPath has_any ("E:\Csharp\SharpMisc\GetBrowserHistory\obj\Debug\GetBrowserHistory.pdb", "C:\Windows\Microsoft.NET\Framework", "E:\Csharp\Thomas\Server\ThomasOneDrive\obj\Release\OneDrive.pdb", "C:\Users\Public\Libraries\thomas.log", "C:\ProgramData\Microsoft\WDF\MDE.dat"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("E:\Csharp\SharpMisc\GetBrowserHistory\obj\Debug\GetBrowserHistory.pdb", "C:\Windows\Microsoft.NET\Framework", "E:\Csharp\Thomas\Server\ThomasOneDrive\obj\Release\OneDrive.pdb", "C:\Users\Public\Libraries\thomas.log", "C:\ProgramData\Microsoft\WDF\MDE.dat", "C:\ProgramData\Microsoft\WDF\pmp.exe", "C:\ProgramData\Microsoft\WDF\mfd.dat", "C:\Windows\Temp\TS_D418.tmp") or FileName in~ ("oci.dll", "mscorsvc.dll", "sharedreg.dll", "uevappmonitor.exe", "sharedreg12.dll", "pmp.exe", "serv.dll", "msi.dll", "amsi.dll", "tcoedge.exe", "rtlwvern.exe", "hpsmartadapter.exe", "hputils.exe", "igccsvc.exe", "adobehelper.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `118.107.234.29`, `118.107.234.26`, `103.159.132.30`, `101.99.88.113`, `101.99.88.188`, `38.54.17.131`, `server.com`, `stub.com` _(+2 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `D53FCC01038E20193FBD51B7400075CF7C9C4402B73DA7B0DB836B000EBD8B1C`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
