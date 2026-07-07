# [CRIT] ToddyCat: your hidden email assistant. Part 2

**Source:** Securelist (Kaspersky)
**Published:** 2026-06-30
**Article:** https://securelist.com/toddycat-apt-umbrij-tool-and-oauth/120251/

## Threat Profile

Table of Contents
Introduction 
Umbrij 
Execution 
Environment preparation 
Acquiring the authorization code 
Results 
Detection 
DLL sideloading 
Browser launch 
Revoking third-party access 
Risk mitigation 
Takeaways 
Indicators of compromise 
Authors
Andrey Gunkin 
Introduction 
We continue to share details on the malicious techniques and toolsets used by the ToddyCat APT group. In the first part of this report , we examined the group’s attacks aimed at stealing data from browsers, as well as…

## Indicators of Compromise (high-fidelity only)

- **MD5:** `1AB58838E5790EFB22F2D35AB98C0B7D`
- **MD5:** `A7D7D6C4C3F227F7117261C63B9E23A9`
- **MD5:** `3D3A621F852C42D97FD7260681E42508`
- **MD5:** `3432DD9AC0DF80EF86EB80BD080F839B`
- **MD5:** `22AAEB4946BA6D2F2E27FEB7DBB295DE`
- **MD5:** `F61FBFB7AA1CD5DC8F70B055B51563E2`
- **MD5:** `F169D6D172DFB775895A5E2B1540C854`
- **MD5:** `9F5F2F0FB0A7F5AA9F16B9A7B6DAD89F`
- **MD5:** `28CB7B261F4EB97E8A4B3B0D32F8DEF1`
- **MD5:** `BAE82A15D1DBFB024617B9B56A8E5F66`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1036.004** — Masquerading: Masquerade Task or Service
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1134.003** — Access Token Manipulation: Make and Impersonate Token
- **T1185** — Browser Session Hijacking
- **T1114.002** — Email Collection: Remote Email Collection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Masquerading scheduled task 'KasperskyEndpointSecurityEDRAvp' launching a signed binary

`UC_124_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*KasperskyEndpointSecurityEDRAvp*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
(DeviceProcessEvents | where Timestamp > ago(30d) | where ProcessCommandLine has "KasperskyEndpointSecurityEDRAvp" | project Timestamp, DeviceName, AccountName, Evidence=ProcessCommandLine, InitiatingProcessFileName),
(DeviceRegistryEvents | where Timestamp > ago(30d) | where RegistryKey has @"\TaskCache\" and RegistryKey has "KasperskyEndpointSecurityEDRAvp" | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, Evidence=RegistryKey, InitiatingProcessFileName)
| order by Timestamp desc
```

### ToddyCat Umbrij DLL side-loading: signed host loading malicious log.dll/GoogleServices.dll from writable path

`UC_124_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="BDSubWiz.exe" OR Processes.process_name="bds.exe" OR Processes.process_name="VSTestVideoRecorder.exe" OR Processes.process_name="GoogleDesktop.exe") AND (Processes.process_path="*\\Users\\Public\\*" OR Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\Windows\\Temp\\*" OR Processes.process_path="*\\Windows\\vss\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName in~ ("BDSubWiz.exe","bds.exe") and FileName =~ "log.dll")
     or (InitiatingProcessFileName =~ "VSTestVideoRecorder.exe" and FileName =~ "Microsoft.VisualStudio.QualityTools.VideoRecorderEngine.dll")
     or (InitiatingProcessFileName =~ "GoogleDesktop.exe" and FileName =~ "GoogleServices.dll")
| where FolderPath has_any (@"\Users\Public\", @"\AppData\Local\Temp\", @"\Windows\Temp\", @"\Windows\vss\")
     or MD5 in~ ("4C39087E5229A70F0215AFB8B7083091","22AAEB4946BA6D2F2E27FEB7DBB295DE")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFolderPath, Dll=FileName, DllPath=FolderPath, MD5, SHA256
| order by Timestamp desc
```

### Umbrij command-line switches (-deepsearch / -runas-currentuser / -debugport / -domainAd / -savepdf)

`UC_124_8` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*-deepsearch*" OR Processes.process="*-runas-currentuser*" OR Processes.process="*-domainAd*" OR Processes.process="*-savepdf*" OR (Processes.process="*-debugport*" AND Processes.process="*-browser*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has_any ("-deepsearch","-runas-currentuser","-domainAd","-savepdf")
   or (ProcessCommandLine has "-debugport" and ProcessCommandLine has "-browser")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

### Chromium browser launched headless with --remote-debugging-port by a non-browser parent (STRD)

`UC_124_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="chrome.exe" OR Processes.process_name="msedge.exe" OR Processes.process_name="chromium.exe") AND Processes.process="*--remote-debugging-port*" AND (Processes.process="*--headless*" OR Processes.parent_process_name="BDSubWiz.exe" OR Processes.parent_process_name="bds.exe" OR Processes.parent_process_name="VSTestVideoRecorder.exe" OR Processes.parent_process_name="GoogleDesktop.exe") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName in~ ("chrome.exe","msedge.exe","chromium.exe","brave.exe")
| where ProcessCommandLine has "--remote-debugging-port"
| where InitiatingProcessFileName in~ ("BDSubWiz.exe","bds.exe","VSTestVideoRecorder.exe","GoogleDesktop.exe")
     or ProcessCommandLine has "--headless"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine
| order by Timestamp desc
```

### Sideload-host binary connecting to Google OAuth/Gmail API endpoints (token exchange)

`UC_124_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name="BDSubWiz.exe" OR All_Traffic.process_name="bds.exe" OR All_Traffic.process_name="VSTestVideoRecorder.exe" OR All_Traffic.process_name="GoogleDesktop.exe") AND (All_Traffic.dest="*googleapis.com*" OR All_Traffic.dest="*accounts.google.com*") by All_Traffic.src All_Traffic.dest All_Traffic.process_name All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("BDSubWiz.exe","bds.exe","VSTestVideoRecorder.exe","GoogleDesktop.exe")
| where RemoteUrl has_any ("oauth2.googleapis.com","accounts.google.com","www.googleapis.com","gmail.googleapis.com","googleapis.com")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort
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

### Article-specific behavioural hunt — ToddyCat: your hidden email assistant. Part 2

`UC_124_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — ToddyCat: your hidden email assistant. Part 2 ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bdsubwiz.exe","log.dll","vstestvideorecorder.exe","qualitytools.videorecorderengine.dll","googledesktop.exe","googleservices.dll","bds.exe") OR Processes.process_path="*\Users\Public\BDSubWiz.exe*" OR Processes.process_path="*%LOCALAPPDATA%\Google\Chrome\User*" OR Processes.process_path="*%LOCALAPPDATA%\Microsoft\Edge\User*" OR Processes.process_path="*%LOCALAPPDATA%\Google\Chrome\BackupFiles\*" OR Processes.process_path="*%LOCALAPPDATA%\Microsoft\Edge\BackupFiles\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*\Users\Public\BDSubWiz.exe*" OR Filesystem.file_path="*%LOCALAPPDATA%\Google\Chrome\User*" OR Filesystem.file_path="*%LOCALAPPDATA%\Microsoft\Edge\User*" OR Filesystem.file_path="*%LOCALAPPDATA%\Google\Chrome\BackupFiles\*" OR Filesystem.file_path="*%LOCALAPPDATA%\Microsoft\Edge\BackupFiles\*" OR Filesystem.file_path="*\AppData\Local\Google\Chrome\User*" OR Filesystem.file_path="*\AppData\Local\Temp\BDS.exe*" OR Filesystem.file_path="*\AppData\Local\Temp\log.dll*" OR Filesystem.file_name IN ("bdsubwiz.exe","log.dll","vstestvideorecorder.exe","qualitytools.videorecorderengine.dll","googledesktop.exe","googleservices.dll","bds.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\Software\\Policies\\Google\\Chrome\\DeveloperToolsAvailability*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — ToddyCat: your hidden email assistant. Part 2
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bdsubwiz.exe", "log.dll", "vstestvideorecorder.exe", "qualitytools.videorecorderengine.dll", "googledesktop.exe", "googleservices.dll", "bds.exe") or FolderPath has_any ("\Users\Public\BDSubWiz.exe", "%LOCALAPPDATA%\Google\Chrome\User", "%LOCALAPPDATA%\Microsoft\Edge\User", "%LOCALAPPDATA%\Google\Chrome\BackupFiles\", "%LOCALAPPDATA%\Microsoft\Edge\BackupFiles\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("\Users\Public\BDSubWiz.exe", "%LOCALAPPDATA%\Google\Chrome\User", "%LOCALAPPDATA%\Microsoft\Edge\User", "%LOCALAPPDATA%\Google\Chrome\BackupFiles\", "%LOCALAPPDATA%\Microsoft\Edge\BackupFiles\", "\AppData\Local\Google\Chrome\User", "\AppData\Local\Temp\BDS.exe", "\AppData\Local\Temp\log.dll") or FileName in~ ("bdsubwiz.exe", "log.dll", "vstestvideorecorder.exe", "qualitytools.videorecorderengine.dll", "googledesktop.exe", "googleservices.dll", "bds.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\Software\Policies\Google\Chrome\DeveloperToolsAvailability")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1AB58838E5790EFB22F2D35AB98C0B7D`, `A7D7D6C4C3F227F7117261C63B9E23A9`, `3D3A621F852C42D97FD7260681E42508`, `3432DD9AC0DF80EF86EB80BD080F839B`, `22AAEB4946BA6D2F2E27FEB7DBB295DE`, `F61FBFB7AA1CD5DC8F70B055B51563E2`, `F169D6D172DFB775895A5E2B1540C854`, `9F5F2F0FB0A7F5AA9F16B9A7B6DAD89F` _(+2 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
