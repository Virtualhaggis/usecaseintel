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
- **MD5:** `1F65544978B8EA0E745E573B8EE9684B`
- **MD5:** `24FCEBDEECBA65004FDB0923763D74FD`
- **MD5:** `D98F568496512E4F98670C61C97CB07A`
- **MD5:** `AA3086BE652C8B20B0B29B2730D57119`
- **MD5:** `A514D1BB62D7916475946FE7C07AC0AA`
- **MD5:** `9CBD560F820C95D7C38342CD558CB5C6`
- **MD5:** `C559CC68986933200FD5D9E4388E2F58`
- **MD5:** `B3352B42432DEDC4A519F011DC8B5D5A`
- **MD5:** `9C872A0D5D5A38950E8B9AC9B488BE3F`

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

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

`UC_16_9` · phase: **exploit** · confidence: **High**

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
  - file hash IOC(s): `1F65544978B8EA0E745E573B8EE9684B`, `24FCEBDEECBA65004FDB0923763D74FD`, `D98F568496512E4F98670C61C97CB07A`, `AA3086BE652C8B20B0B29B2730D57119`, `A514D1BB62D7916475946FE7C07AC0AA`, `9CBD560F820C95D7C38342CD558CB5C6`, `C559CC68986933200FD5D9E4388E2F58`, `B3352B42432DEDC4A519F011DC8B5D5A` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 10 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
