# [CRIT] StrikeShark: investigating a new campaign delivering Cobalt Strike through SharkLoader

**Source:** Securelist (Kaspersky)
**Published:** 2026-06-24
**Article:** https://securelist.com/strikeshark-campaign/120326/

## Threat Profile

Table of Contents
Introduction 
Initial infection 
Exploitation of public-facing applications 
Dropper-based distribution 
SharkLoader installation 
SharkLoader DLL – Main implant 
“PerfectDLL Hijacking” technique 
Decryption and loading of >DscCoreR.mui 
DscCoreR.mui and SyncRes.dat DLLs 
Decryption and loading of SyncRes.dat 
SyncRes.dat decrypted DLL: Multiple API hooks 
VEH registration and access violation handling 
Thread creation for Cobalt Strike Beacon execution 
MinHook DLL, API hookin…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-26855`
- **CVE:** `CVE-2023-32315`
- **CVE:** `CVE-2024-36401`
- **CVE:** `CVE-2016-4437`
- **CVE:** `CVE-2021-36260`
- **CVE:** `CVE-2021-27076`
- **CVE:** `CVE-2022-27925`
- **CVE:** `CVE-2022-41082`
- **CVE:** `CVE-2023-46747`
- **CVE:** `CVE-2024-21762`
- **CVE:** `CVE-2025-55182`
- **CVE:** `CVE-2022-40684`
- **CVE:** `CVE-2023-20198`
- **Domain (defanged):** `connect-microsoft.com`
- **Domain (defanged):** `ms-record.com`
- **Domain (defanged):** `ms-record.top`
- **Domain (defanged):** `ms-tray.top`
- **MD5:** `c559cc68986933200fd5d9e4388e2f58`
- **MD5:** `b3352b42432dedc4a519f011dc8b5d5a`
- **MD5:** `24fcebdeecba65004fdb0923763d74fd`
- **MD5:** `9c872a0d5d5a38950e8b9ac9b488be3f`
- **MD5:** `aa3086be652c8b20b0b29b2730d57119`
- **MD5:** `a514d1bb62d7916475946fe7c07ac0aa`
- **MD5:** `9cbd560f820c95d7c38342cd558cb5c6`
- **MD5:** `d98f568496512e4f98670c61c97cb07a`
- **MD5:** `1f65544978b8ea0e745e573b8ee9684b`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1190** — Exploit Public-Facing Application
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1140** — Deobfuscate/Decode Files or Information
- **T1505.003** — Server Software Component: Web Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1204.002** — User Execution: Malicious File
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SystemSettings.exe executing from non-standard path (SharkLoader DLL side-load host)

`UC_109_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="SystemSettings.exe" by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where NOT (like(process_path,"%\\Windows\\ImmersiveControlPanel\\%") OR like(process_path,"%\\Windows\\WinSxS\\%")) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | table firstTime lastTime dest user process_name process_path process parent_process_name count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "SystemSettings.exe"
| where FolderPath !startswith @"C:\Windows\ImmersiveControlPanel\" and FolderPath !has @"\WinSxS\"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### SharkLoader encrypted payload files dropped (DscCoreR.mui + SyncRes.dat + SystemSettings.dll)

`UC_109_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("SystemSettings.dll","DscCoreR.mui","SyncRes.dat") (Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*\\Users\\Public\\*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | stats dc(file_name) as distinct_components values(file_name) as files values(file_path) as paths min(firstTime) as firstTime by dest process_name | where distinct_components >= 1 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("SystemSettings.dll","DscCoreR.mui","SyncRes.dat")
| where FolderPath has_any (@"\ProgramData\", @"\AppData\", @"\Users\Public\")
| where not(FileName =~ "SystemSettings.dll" and FolderPath startswith @"C:\Windows\")
| summarize Components=make_set(FileName), Paths=make_set(FolderPath), DistinctComponents=dcount(FileName), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by LastSeen desc
```

### Web server process spawning command shell to relocate SystemSettings.exe (post-webshell staging)

`UC_109_12` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("w3wp.exe","java.exe","httpd.exe","tomcat9.exe","UMWorkerProcess.exe","MSExchangeFrontEndTransport.exe") Processes.process="*SystemSettings.exe*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | table firstTime dest user parent_process_name process_name process count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("w3wp.exe","java.exe","httpd.exe","tomcat9.exe","UMWorkerProcess.exe","MSExchangeFrontEndTransport.exe")
| where ProcessCommandLine has "SystemSettings.exe"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### SharkLoader dropper masquerading as Cisco AnyConnect / Google Update installer

`UC_109_13` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("GoogleUpdateStepup.exe","AutoUpdate.exe") OR Processes.process="*AnyConnect-win-4.10.04071-predeploy-k9*") (Processes.process_path="*\\AppData\\*" OR Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\ProgramData\\*") by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | table firstTime dest user process_name process_path process parent_process_name count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("GoogleUpdateStepup.exe","AutoUpdate.exe")) or ProcessCommandLine matches regex @"(?i)AnyConnect-win-4\.10\.04071-predeploy-k9"
| where FolderPath has_any (@"\AppData\", @"\Downloads\", @"\Temp\", @"\ProgramData\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Scheduled task persistence launching relocated SystemSettings.exe (SharkLoader)

`UC_109_14` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" Processes.process="*SystemSettings.exe*" Processes.process="*/create*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | table firstTime dest user process parent_process_name count
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create" and ProcessCommandLine has "SystemSettings.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### SharkLoader / Cobalt Strike C2 egress to StrikeShark lookalike domains

`UC_109_15` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*connect-microsoft.com" OR DNS.query="*ms-record.com" OR DNS.query="*ms-record.top" OR DNS.query="*ms-tray.top") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | table firstTime src query count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("connect-microsoft.com","ms-record.com","ms-record.top","ms-tray.top")
    or (InitiatingProcessFileName =~ "SystemSettings.exe" and InitiatingProcessFolderPath !startswith @"C:\Windows\" and RemoteIPType == "Public")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — StrikeShark: investigating a new campaign delivering Cobalt Strike through Shark

`UC_109_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — StrikeShark: investigating a new campaign delivering Cobalt Strike through Shark ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("systemsettings.exe","systemsettings.dll","googleupdatestepup.exe","autoupdate.exe","anyconnect-win-4.msi","msedge.dll","printdialog.dll","miracastview.dll",".pdf.exe","ntdll.dll","selfname.exe","procdump64.exe") OR Processes.process_path="*C:\Windows\ImmersiveControlPanel\*" OR Processes.process_path="*C:\ProgramData\KasperskyLab\*" OR Processes.process_path="*%APPDATA%\reports\AnyConnect-win-4.msi*" OR Processes.process_path="*C:\Windows\ImmersiveControlPanel*" OR Processes.process_path="*C:\ADriveLogs_Logs\SystemSettings.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\ImmersiveControlPanel\*" OR Filesystem.file_path="*C:\ProgramData\KasperskyLab\*" OR Filesystem.file_path="*%APPDATA%\reports\AnyConnect-win-4.msi*" OR Filesystem.file_path="*C:\Windows\ImmersiveControlPanel*" OR Filesystem.file_path="*C:\ADriveLogs_Logs\SystemSettings.exe*" OR Filesystem.file_path="*\inetpub\custerr*" OR Filesystem.file_path="*\inetpub\wwwroot\*" OR Filesystem.file_name IN ("systemsettings.exe","systemsettings.dll","googleupdatestepup.exe","autoupdate.exe","anyconnect-win-4.msi","msedge.dll","printdialog.dll","miracastview.dll",".pdf.exe","ntdll.dll","selfname.exe","procdump64.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — StrikeShark: investigating a new campaign delivering Cobalt Strike through Shark
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("systemsettings.exe", "systemsettings.dll", "googleupdatestepup.exe", "autoupdate.exe", "anyconnect-win-4.msi", "msedge.dll", "printdialog.dll", "miracastview.dll", ".pdf.exe", "ntdll.dll", "selfname.exe", "procdump64.exe") or FolderPath has_any ("C:\Windows\ImmersiveControlPanel\", "C:\ProgramData\KasperskyLab\", "%APPDATA%\reports\AnyConnect-win-4.msi", "C:\Windows\ImmersiveControlPanel", "C:\ADriveLogs_Logs\SystemSettings.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\ImmersiveControlPanel\", "C:\ProgramData\KasperskyLab\", "%APPDATA%\reports\AnyConnect-win-4.msi", "C:\Windows\ImmersiveControlPanel", "C:\ADriveLogs_Logs\SystemSettings.exe", "\inetpub\custerr", "\inetpub\wwwroot\") or FileName in~ ("systemsettings.exe", "systemsettings.dll", "googleupdatestepup.exe", "autoupdate.exe", "anyconnect-win-4.msi", "msedge.dll", "printdialog.dll", "miracastview.dll", ".pdf.exe", "ntdll.dll", "selfname.exe", "procdump64.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `connect-microsoft.com`, `ms-record.com`, `ms-record.top`, `ms-tray.top`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-26855`, `CVE-2023-32315`, `CVE-2024-36401`, `CVE-2016-4437`, `CVE-2021-36260`, `CVE-2021-27076`, `CVE-2022-27925`, `CVE-2022-41082` _(+5 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `c559cc68986933200fd5d9e4388e2f58`, `b3352b42432dedc4a519f011dc8b5d5a`, `24fcebdeecba65004fdb0923763d74fd`, `9c872a0d5d5a38950e8b9ac9b488be3f`, `aa3086be652c8b20b0b29b2730d57119`, `a514d1bb62d7916475946fe7c07ac0aa`, `9cbd560f820c95d7c38342cd558cb5c6`, `d98f568496512e4f98670c61c97cb07a` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 16 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
