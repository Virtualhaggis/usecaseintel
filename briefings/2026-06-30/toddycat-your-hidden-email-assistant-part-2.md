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
- **T1185** — Browser Session Hijacking
- **T1539** — Steal Web Session Cookie
- **T1134.003** — Access Token Manipulation: Make and Impersonate Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ToddyCat Umbrij scheduled task masquerading as Kaspersky EDR (KasperskyEndpointSecurityEDRAvp)

`UC_3_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(index=* source="WinEventLog:Security") EventCode=4698 Task_Name="*KasperskyEndpointSecurityEDRAvp*"
| table _time, host, Task_Name, Caller_User_Name, Account_Name, Command
| sort - _time
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "ScheduledTaskCreated"
| where AdditionalFields has "KasperskyEndpointSecurityEDRAvp"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
```

### ToddyCat Umbrij DLL sideload — signed host EXE loading attacker DLL from writable path

`UC_3_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(index=* source="*WinEventLog:*Sysmon*") EventCode=7
((Image="*\\BDSubWiz.exe" ImageLoaded="*\\log.dll") OR (Image="*\\VSTestVideoRecorder.exe" ImageLoaded="*\\Microsoft.VisualStudio.QualityTools.VideoRecorderEngine.dll") OR (Image="*\\GoogleDesktop.exe" ImageLoaded="*\\GoogleServices.dll"))
| search (ImageLoaded="*\\Users\\Public\\*" OR ImageLoaded="*\\Windows\\vss\\*" OR Image="*\\Users\\Public\\*" OR Image="*\\Windows\\vss\\*")
| table _time, host, Image, ImageLoaded, Signed, SignatureStatus
| sort - _time
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where (InitiatingProcessFileName =~ "BDSubWiz.exe" and FileName =~ "log.dll")
     or (InitiatingProcessFileName =~ "VSTestVideoRecorder.exe" and FileName =~ "Microsoft.VisualStudio.QualityTools.VideoRecorderEngine.dll")
     or (InitiatingProcessFileName =~ "GoogleDesktop.exe" and FileName =~ "GoogleServices.dll")
| where InitiatingProcessFolderPath has_any (@"\Users\Public\", @"\Windows\vss\") or FolderPath has_any (@"\Users\Public\", @"\Windows\vss\")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### ToddyCat STRD — Chromium browser launched with --remote-debugging-port by non-browser parent

`UC_3_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("chrome.exe","msedge.exe","brave.exe")) Processes.process="*--remote-debugging-port*" NOT (Processes.parent_process_name IN ("explorer.exe","chrome.exe","msedge.exe","brave.exe","userinit.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("chrome.exe","msedge.exe","brave.exe")
| where ProcessCommandLine has "--remote-debugging-port"
| where InitiatingProcessFileName in~ ("BDSubWiz.exe","VSTestVideoRecorder.exe","GoogleDesktop.exe","bds.exe")
     or InitiatingProcessFileName !in~ ("explorer.exe","chrome.exe","msedge.exe","brave.exe","userinit.exe","svchost.exe")
| extend Headless = ProcessCommandLine has_any ("--headless","--remote-debugging-pipe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, ProcessCommandLine, Headless
| order by Timestamp desc
```

### ToddyCat Umbrij command-line parameters (-deepsearch/-regex/-debugport/-browser/-domainAd)

`UC_3_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process="*-deepsearch*" AND Processes.process="*-regex*") OR (Processes.process="*-debugport*" AND Processes.process="*-browser*") OR Processes.process="*-runas-currentuser*" OR Processes.process="*-domainAd*" OR Processes.process="*-savepdf*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "-deepsearch" and ProcessCommandLine has "-regex")
     or (ProcessCommandLine has "-debugport" and ProcessCommandLine has "-browser")
     or (ProcessCommandLine has "-browser" and ProcessCommandLine has "-path" and ProcessCommandLine has_any ("both","msedge","chrome"))
     or ProcessCommandLine has "-runas-currentuser"
     or ProcessCommandLine has "-domainAd"
     or ProcessCommandLine has "-savepdf"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, SHA256
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

`UC_3_5` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
