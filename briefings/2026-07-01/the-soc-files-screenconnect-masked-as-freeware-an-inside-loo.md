# [HIGH] The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale campaign

**Source:** Securelist (Kaspersky)
**Published:** 2026-07-01
**Article:** https://securelist.com/tr/the-soc-files-screenconnect-campaign-with-asyncrat/120472/

## Threat Profile

Threat Response 
Table of Contents
Introduction 
Initial incident investigation 
How ScreenConnect entered the system 
Expanding the investigation 
Fake domain infrastructure 
Cluster 1: 162.216.241[.]242 and 198.23.185[.]81 
Cluster 2: 2.59.134[.]97 
C2 infrastructure analysis 
Takeaways 
Detection by Kaspersky solutions 
Indicators of compromise 
Loaders 
Malicious library: install.res.1033.dll 
AsyncRAT C2 
Fake websites addresses 
Fake domain infrastructure 
ScreenConnect C2 
Introduction 
T…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `162.216.241.242`
- **IPv4 (defanged):** `198.23.185.81`
- **IPv4 (defanged):** `2.59.134.97`
- **Domain (defanged):** `mora1987.work.gd`
- **Domain (defanged):** `r.servermanagemen.xyz`
- **Domain (defanged):** `fileget.loseyourip.com`
- **Domain (defanged):** `direct-download.giize.com`
- **Domain (defanged):** `studioobs.com`
- **MD5:** `87603ea025623b19954e460add532048`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1053.005** — Scheduled Task
- **T1543.003** — Windows Service
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1608.006** — Stage Capabilities: SEO Poisoning
- **T1189** — Drive-by Compromise
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1036.008** — Masquerading: Masquerade File Type
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1548.002** — Abuse Elevation Control Mechanism: Bypass UAC
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1620** — Reflective Code Loading
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1055.012** — Process Injection: Process Hollowing
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Fake OBS/DS4Windows freeware archive downloaded from typosquatted ScreenConnect-delivery infra

`UC_233_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="obs-studio-windows-x64.zip" OR Filesystem.file_path="*obs-studio-windows-full*") OR Filesystem.file_path IN ("*studioobs.com*","*fileget.loseyourip.com*","*direct-download.giize.com*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".zip" or FileName endswith ".exe"
| where FileOriginUrl has_any ("studioobs.com","fileget.loseyourip.com","direct-download.giize.com","obs-studio-windows-full")
   or FileName =~ "obs-studio-windows-x64.zip"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, FileOriginUrl, FileOriginReferrerUrl, SHA256
| order by Timestamp desc
```

### DLL side-load of install.res.1033.dll via renamed Microsoft install.exe (ScreenConnect loader)

`UC_233_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="install.exe" OR Processes.original_file_name="install.exe" by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | search process="*install.res.1033.dll*" OR process="*OBS-Studio-Installer*" OR process="*vcredist_x64.dll*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "install.res.1033.dll"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          LoadedDll = FolderPath,
          Loader = InitiatingProcessFileName,
          LoaderPath = InitiatingProcessFolderPath,
          LoaderCmd = InitiatingProcessCommandLine,
          LoaderMD5 = InitiatingProcessMD5, SHA256
| order by Timestamp desc
```

### msiexec silently installing MSI packages renamed as .dll (vcredist_x64.dll / vcredist_x86.dll)

`UC_233_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="msiexec.exe" (Processes.process="*vcredist_x64.dll*" OR Processes.process="*vcredist_x86.dll*") Processes.process="*/i*" by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "msiexec.exe"
| where ProcessCommandLine has "/i"
| where ProcessCommandLine has_any ("vcredist_x64.dll","vcredist_x86.dll")
| where ProcessCommandLine has ".dll"
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ProcessCommandLine, SHA256
| order by Timestamp desc
```

### ScreenConnect-spawned PowerShell adds Defender exclusions and disables UAC (Fj5NmEsp9EuKrun.ps1)

`UC_233_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") (Processes.process="*Add-MpPreference*ExclusionPath*" OR Processes.process="*Set-MpPreference*" OR Processes.process="*ExclusionProcess*RegAsm.exe*" OR Processes.process="*ConsentPromptBehaviorAdmin*" OR Processes.process="*Fj5NmEsp9EuKrun*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where InitiatingProcessFileName has_any ("ScreenConnect","ConnectWiseControl")
   or ProcessCommandLine has "Fj5NmEsp9EuKrun"
| where ProcessCommandLine has_any ("Add-MpPreference","ExclusionPath","ExclusionProcess","ConsentPromptBehaviorAdmin","RegAsm.exe",@"C:\Users\Public")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          ProcessCommandLine
| order by Timestamp desc
```

### ScreenConnect service drops and executes VBS/PS loader files in C:\Users\Public

`UC_233_12` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("wscript.exe","cscript.exe","powershell.exe") (Processes.process="*C:\\Users\\Public\\script.vbs*" OR Processes.process="*C:\\Users\\Public\\cap.ps1*" OR Processes.process="*secret_bytes.txt*" OR Processes.process="*installer_method3_stream.vbs*") by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let loaderFiles = dynamic(["script.vbs","cap.ps1","secret_bytes.txt","msgbox.txt","1.vb","installer_method3_stream.vbs"]);
union
( DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName in~ ("wscript.exe","cscript.exe","powershell.exe")
  | where ProcessCommandLine has @"C:\Users\Public" and ProcessCommandLine has_any ("script.vbs","cap.ps1","secret_bytes.txt","installer_method3_stream.vbs")
  | project Timestamp, DeviceName, AccountName, Parent = InitiatingProcessFileName, ProcessCommandLine ),
( DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath startswith @"C:\Users\Public" and FileName in~ (loaderFiles)
  | where InitiatingProcessFileName has_any ("ScreenConnect","ConnectWiseControl","wscript.exe")
  | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Parent = InitiatingProcessFileName, ProcessCommandLine = InitiatingProcessCommandLine, FileName, FolderPath )
| order by Timestamp desc
```

### Scheduled task MasterPackager.Updater re-launching wscript C:\Users\Public\script.vbs every 2 minutes

`UC_233_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" Processes.process="*MasterPackager.Updater*" Processes.process="*script.vbs*" by Processes.dest Processes.user Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "MasterPackager.Updater"
   or (ProcessCommandLine has "/Create" and ProcessCommandLine has @"C:\Users\Public\script.vbs" and ProcessCommandLine has "wscript")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          ProcessCommandLine
| order by Timestamp desc
```

### RegAsm.exe (hollowed) beaconing to AsyncRAT C2 / ScreenConnect infra contacts campaign IPs

`UC_233_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("162.216.241.242","198.23.185.81","2.59.134.97") OR All_Traffic.dest="mora1987.work.gd" OR All_Traffic.dest="r.servermanagemen.xyz") OR (All_Traffic.app="regasm.exe" AND All_Traffic.dest_is_internal="false") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let c2ip = dynamic(["162.216.241.242","198.23.185.81","2.59.134.97"]);
let c2dom = dynamic(["mora1987.work.gd","r.servermanagemen.xyz"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (c2ip)
   or RemoteUrl has_any (c2dom)
   or (InitiatingProcessFileName =~ "RegAsm.exe" and RemoteIPType == "Public")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl
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

### Service install for persistence — sc.exe / new service registry write

`UC_SERVICE_PERSIST` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="sc.exe" AND Processes.process="*create*"
      AND (Processes.process="*\Users\*" OR Processes.process="*\AppData\*"
        OR Processes.process="*\ProgramData\*" OR Processes.process="*\Temp\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| append
    [| tstats `summariesonly` count from datamodel=Endpoint.Registry
        where Registry.registry_path="*\\SYSTEM\\CurrentControlSet\\Services\\*"
          AND Registry.registry_value_name="ImagePath"
          AND (Registry.registry_value_data="*\Users\*"
            OR Registry.registry_value_data="*\AppData\*"
            OR Registry.registry_value_data="*\Temp\*")
        by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.user
     | `drop_dm_object_name(Registry)`]
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "sc.exe" and ProcessCommandLine has "create"
| where ProcessCommandLine matches regex @"(?i)(\Users\|\AppData\|\ProgramData\|\Temp\)"
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

### Article-specific behavioural hunt — The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale

`UC_233_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("install.res.1033.dll","fj5nmesp9eukrun.ps1","regasm.exe","installer_method3_stream.vbs","cap.ps1","script.vbs","obs-studio-installer.exe","vcredist_x64.dll","vcredist_x86.dll","ds4windows.exe","crosshairx_installer.exe","jumper.exe","pro.exe","processhacker-2.39-setup.exe","clientservice.exe") OR Processes.process_path="*C:\Users\Public\script.vbs*" OR Processes.process_path="*C:\Temp\OBS-Studio-Windows-x64\Assets\x86\vcredist_x64.dll*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Users\Public\script.vbs*" OR Filesystem.file_path="*C:\Temp\OBS-Studio-Windows-x64\Assets\x86\vcredist_x64.dll*" OR Filesystem.file_name IN ("install.res.1033.dll","fj5nmesp9eukrun.ps1","regasm.exe","installer_method3_stream.vbs","cap.ps1","script.vbs","obs-studio-installer.exe","vcredist_x64.dll","vcredist_x86.dll","ds4windows.exe","crosshairx_installer.exe","jumper.exe","pro.exe","processhacker-2.39-setup.exe","clientservice.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The SOC Files: ScreenConnect masked as freeware. An inside look at a large-scale
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("install.res.1033.dll", "fj5nmesp9eukrun.ps1", "regasm.exe", "installer_method3_stream.vbs", "cap.ps1", "script.vbs", "obs-studio-installer.exe", "vcredist_x64.dll", "vcredist_x86.dll", "ds4windows.exe", "crosshairx_installer.exe", "jumper.exe", "pro.exe", "processhacker-2.39-setup.exe", "clientservice.exe") or FolderPath has_any ("C:\Users\Public\script.vbs", "C:\Temp\OBS-Studio-Windows-x64\Assets\x86\vcredist_x64.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Users\Public\script.vbs", "C:\Temp\OBS-Studio-Windows-x64\Assets\x86\vcredist_x64.dll") or FileName in~ ("install.res.1033.dll", "fj5nmesp9eukrun.ps1", "regasm.exe", "installer_method3_stream.vbs", "cap.ps1", "script.vbs", "obs-studio-installer.exe", "vcredist_x64.dll", "vcredist_x86.dll", "ds4windows.exe", "crosshairx_installer.exe", "jumper.exe", "pro.exe", "processhacker-2.39-setup.exe", "clientservice.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `162.216.241.242`, `198.23.185.81`, `2.59.134.97`, `mora1987.work.gd`, `r.servermanagemen.xyz`, `fileget.loseyourip.com`, `direct-download.giize.com`, `studioobs.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `87603ea025623b19954e460add532048`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
