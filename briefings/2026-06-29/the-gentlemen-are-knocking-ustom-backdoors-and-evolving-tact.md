# [CRIT] The Gentlemen are knocking: сustom backdoors and evolving tactics

**Source:** Securelist (Kaspersky)
**Published:** 2026-06-29
**Article:** https://securelist.com/the-gentlemen-raas/120447/

## Threat Profile

Table of Contents
Introduction 
Technical details 
Initial infection vector 
Reconnaissance 
Lateral movement 
Disabling security products 
Go-based backdoor 
Go-based ransomware 
Automated system execution prevention 
Lateral movement through GPO deployment 
Lateral movement through PsExec 
Pre-encryption activities 
Encryption process 
C-based ransomware 
Victims 
Attribution 
Conclusion 
Indicators of compromise 
Go ransomware 
C-based ransomware 
Backdoor 
Vulnerable drivers 
Scanning tools …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `81.177.215.15`
- **Domain (defanged):** `live.sysinternals.com`
- **Domain (defanged):** `domain.com`
- **MD5:** `3B46A729DB7AE6AF8B19711C9452194D`
- **MD5:** `02944C8A5535CDB5B2CBB893DB2D5ACF`
- **MD5:** `10CA9A4040001560D053B7E7885C1B95`
- **MD5:** `3C471EBC947CDF32240A90FFADF49B13`
- **MD5:** `4BE8BB62F0EBBCF4CE52C35AB6F794F5`
- **MD5:** `53C616677BC7E2A0A03127F19166D007`
- **MD5:** `5C3B9821FC82A9028CB63B9671950919`
- **MD5:** `5F0B2C6D9F442754258BF4DD841C8341`
- **MD5:** `608FAF58353B65C45EF9833358AC3787`
- **MD5:** `6AE7C9A7EA0B8C40A64225734F6BD01D`
- **MD5:** `846DC77C1246DB20D976346E0E359502`
- **MD5:** `ADAC9984B3CC43D66A0D33079BBEC299`
- **MD5:** `AE0E536766788478263BF448A9381641`
- **MD5:** `B3E418D30312C1B2C58A791286868F42`
- **MD5:** `C2764744DCB4B0E1DB79CA1E8BF65368`
- **MD5:** `D12A5B36DD00586CC374A1CAE43EFED4`
- **MD5:** `D2F72897E8986303D5567EB2384932B8`
- **MD5:** `DE1522F9219497632F30F8A6E72F26B6`
- **MD5:** `FDAE2BEB813778B4540A997706862096`
- **MD5:** `B9986A0F1F1F1A798DC3F0C59A80A1A3`
- **MD5:** `554E699C96B332468F1AE69C1AE81EF9`
- **MD5:** `5761BD63DA03686FC480245DA7BD1E9F`
- **MD5:** `B6B51508AD6F462C45FE102C85D246C8`
- **MD5:** `8F0577D28C4FF5F71B149F444BFABA8E`
- **MD5:** `525EF6014F0EF20E44FE47C1D9980B69`
- **MD5:** `407B6A136BBAA7172EB44EF9D08BB58A`
- **MD5:** `9321A61A25C7961D9F36852ECAA86F55`
- **MD5:** `73F0A8C3EA794A04E80C32038249F044`
- **MD5:** `EEF8A950952696B018AA9C6DA2F5D7AD`
- **MD5:** `EDB1C480295250DD1A38F3AA1357DEAE`
- **MD5:** `5537C708EDB9A2C21F88E34E8A0F1744`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1053.005** — Scheduled Task
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1053.005** — Persistence (article-specific)
- **T1040** — Network Sniffing
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1571** — Non-Standard Port
- **T1090** — Proxy
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1068** — Exploitation for Privilege Escalation
- **T1484.001** — Domain or Tenant Policy Modification: Group Policy Modification
- **T1570** — Lateral Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### The Gentlemen network sniffing via netsh trace capture redirected to ADMIN$ share

`UC_72_10` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*netsh*" Processes.process="*trace*" (Processes.process="*capture=yes*" OR Processes.process="*ADMIN$*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has "netsh" and ProcessCommandLine has "trace"
| where ProcessCommandLine has_any ("capture=yes", @"\ADMIN$\")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### The Gentlemen Go backdoor C2 beacon to 81.177.215.15 on TCP/9443

`UC_72_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="81.177.215.15" All_Traffic.dest_port=9443 by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "81.177.215.15" and RemotePort == 9443
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, InitiatingProcessAccountName
| order by Timestamp desc
```

### The Gentlemen BYOVD vulnerable driver drop/load (EDR-killer drivers)

`UC_72_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name IN ("ProcessMonitorDriver.sys","wamsdk.sys","gamedriverx64.sys","biontdrv.sys","inpoutx64.sys","wsftprm.sys","Havoc.sys") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName in~ ("ProcessMonitorDriver.sys","wamsdk.sys","gamedriverx64.sys","biontdrv.sys","inpoutx64.sys","wsftprm.sys","Havoc.sys")
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

### The Gentlemen impair defenses via Set-MpPreference exclusions and AV-removal tooling

`UC_72_13` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("kavrmvr.exe","OpenArk64.exe","PowerRun.exe","Allpatch2.exe") OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND Processes.process="*MpPreference*" AND (Processes.process="*DisableRealtimeMonitoring*" OR Processes.process="*EnableControlledFolderAccess Disabled*" OR Processes.process="*ExclusionProcess*" OR Processes.process="*ExclusionPath*"))) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where (FileName in~ ("kavrmvr.exe","OpenArk64.exe","PowerRun.exe","Allpatch2.exe"))
    or (FileName in~ ("powershell.exe","pwsh.exe")
        and ProcessCommandLine has "MpPreference"
        and ProcessCommandLine has_any ("DisableRealtimeMonitoring","EnableControlledFolderAccess Disabled","ExclusionProcess","ExclusionPath"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### The Gentlemen Windows Defender disabled via Policy registry keys

`UC_72_14` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path="*\\Policies\\Microsoft\\Windows Defender*" Registry.registry_value_name IN ("DisableAntiSpyware","DisableBehaviorMonitoring","DisableOnAccessProtection","DisableScanOnRealtimeEnable") Registry.registry_value_data="0x1" by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has @"\Policies\Microsoft\Windows Defender"
| where RegistryValueName in~ ("DisableAntiSpyware","DisableBehaviorMonitoring","DisableOnAccessProtection","DisableScanOnRealtimeEnable")
| where RegistryValueData == "1"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### The Gentlemen ransomware deployment via deploy_gpo.ps1 / NETLOGON staging

`UC_72_15` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*deploy_gpo.ps1*" OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND Processes.process="*\\NETLOGON\\*" AND Processes.process="*.exe*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has "deploy_gpo.ps1"
    or (ProcessCommandLine has @"\NETLOGON\" and ProcessCommandLine has ".exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
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

### Article-specific behavioural hunt — The Gentlemen are knocking: сustom backdoors and evolving tactics

`UC_72_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The Gentlemen are knocking: сustom backdoors and evolving tactics ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("deploy_gpo.ps1","processmonitordriver.sys","wamsdk.sys","gamedriverx64.sys","biontdrv.sys","inpoutx64.sys","wsftprm.sys","havoc.sys","kavrmvr.exe","psexec.exe","dism.exe","takeown.exe","icacls.exe","vssadmin.exe","wevtutil.exe") OR Processes.process="*Add-MpPreference -ExclusionPath*" OR Processes.process="*Set-MpPreference -DisableRealtime*" OR Processes.process_path="*C:\Temp\psexec.exe*" OR Processes.process_path="*C:\Windows\Prefetch\*" OR Processes.process_path="*C:\ProgramData\Microsoft\Windows*" OR Processes.process_path="*%SystemRoot%\System32\LogFiles\RDP*" OR Processes.process_path="*C:\Windows\sysvol\domain\scripts\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Temp\psexec.exe*" OR Filesystem.file_path="*C:\Windows\Prefetch\*" OR Filesystem.file_path="*C:\ProgramData\Microsoft\Windows*" OR Filesystem.file_path="*%SystemRoot%\System32\LogFiles\RDP*" OR Filesystem.file_path="*C:\Windows\sysvol\domain\scripts\*" OR Filesystem.file_name IN ("deploy_gpo.ps1","processmonitordriver.sys","wamsdk.sys","gamedriverx64.sys","biontdrv.sys","inpoutx64.sys","wsftprm.sys","havoc.sys","kavrmvr.exe","psexec.exe","dism.exe","takeown.exe","icacls.exe","vssadmin.exe","wevtutil.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The Gentlemen are knocking: сustom backdoors and evolving tactics
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("deploy_gpo.ps1", "processmonitordriver.sys", "wamsdk.sys", "gamedriverx64.sys", "biontdrv.sys", "inpoutx64.sys", "wsftprm.sys", "havoc.sys", "kavrmvr.exe", "psexec.exe", "dism.exe", "takeown.exe", "icacls.exe", "vssadmin.exe", "wevtutil.exe") or ProcessCommandLine has_any ("Add-MpPreference -ExclusionPath", "Set-MpPreference -DisableRealtime") or FolderPath has_any ("C:\Temp\psexec.exe", "C:\Windows\Prefetch\", "C:\ProgramData\Microsoft\Windows", "%SystemRoot%\System32\LogFiles\RDP", "C:\Windows\sysvol\domain\scripts\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Temp\psexec.exe", "C:\Windows\Prefetch\", "C:\ProgramData\Microsoft\Windows", "%SystemRoot%\System32\LogFiles\RDP", "C:\Windows\sysvol\domain\scripts\") or FileName in~ ("deploy_gpo.ps1", "processmonitordriver.sys", "wamsdk.sys", "gamedriverx64.sys", "biontdrv.sys", "inpoutx64.sys", "wsftprm.sys", "havoc.sys", "kavrmvr.exe", "psexec.exe", "dism.exe", "takeown.exe", "icacls.exe", "vssadmin.exe", "wevtutil.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `81.177.215.15`, `live.sysinternals.com`, `domain.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `3B46A729DB7AE6AF8B19711C9452194D`, `02944C8A5535CDB5B2CBB893DB2D5ACF`, `10CA9A4040001560D053B7E7885C1B95`, `3C471EBC947CDF32240A90FFADF49B13`, `4BE8BB62F0EBBCF4CE52C35AB6F794F5`, `53C616677BC7E2A0A03127F19166D007`, `5C3B9821FC82A9028CB63B9671950919`, `5F0B2C6D9F442754258BF4DD841C8341` _(+23 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
