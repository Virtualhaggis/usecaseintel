# [CRIT] Inside the Modern SOC: The 72-Minute Race

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-06-15
**Article:** https://unit42.paloaltonetworks.com/soc-72-minute-race/

## Threat Profile

Threat Research Center 
Insights 
Inside the Modern SOC 
Inside the Modern SOC 
Inside the Modern SOC: The 72-Minute Race 
4 min read 
Related Products Cortex Cortex XSIAM Managed Threat Hunting Unit 42 Incident Response 
By: Sharon Maydar 
Published: June 15, 2026 
Categories: Inside the Modern SOC 
Insights 
Tags: Identity 
Operation security 
Unit 42 Incident Response Report 
The Speed Gap: Where Strategy Meets Reality 
This marks the beginning of our series, Inside the Modern SOC: Trends and…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556** — Modify Authentication Process
- **T1098.005** — Account Manipulation: Device Registration
- **T1621** — Multi-Factor Authentication Request Generation
- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1578.002** — Modify Cloud Compute Infrastructure: Create Cloud Instance
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1048.003** — Exfiltration Over Alternative Protocol
- **T1490** — Inhibit System Recovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Help-desk-initiated password/MFA reset followed by immediate sign-in from new IP (Scattered Spider)

`UC_7_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as reset_time from datamodel=Change.All_Changes where All_Changes.action="modified" AND All_Changes.object_category="user" AND (All_Changes.command IN ("Reset user password","Change user password","Reset password (self-service)","Update user")) by All_Changes.object, All_Changes.user, All_Changes.src | rename All_Changes.object as target_user All_Changes.user as reset_actor All_Changes.src as reset_src | join type=inner target_user [| tstats summariesonly=true min(_time) as login_time from datamodel=Authentication.Authentication where Authentication.action="success" AND Authentication.app IN ("Office365","AzureActiveDirectory","AAD") by Authentication.user, Authentication.src | rename Authentication.user as target_user Authentication.src as login_src] | where login_time > reset_time AND (login_time - reset_time) <= 1800 AND login_src!=reset_src | eval minutes_between = round((login_time-reset_time)/60,1) | table reset_time, login_time, minutes_between, target_user, reset_actor, reset_src, login_src | sort - login_time
```

**Defender KQL:**
```kql
let WindowMinutes = 30m;
let ResetEvents = IdentityDirectoryEvents
| where Timestamp > ago(7d)
| where ActionType in ("Account Password reset","Password change activity","Reset user password","Update user","Reset password (self-service)")
| where isnotempty(TargetAccountUpn) and AccountUpn != TargetAccountUpn
| project ResetTime = Timestamp, ResetActor = AccountUpn, TargetUpn = TargetAccountUpn, ResetIP = IPAddress;
ResetEvents
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | project LoginTime = Timestamp, AccountUpn, LoginIP = IPAddress, Country, City, DeviceName, AadDeviceId, UserAgent, AppDisplayName, IsCompliantUser
) on $left.TargetUpn == $right.AccountUpn
| where LoginTime between (ResetTime .. ResetTime + WindowMinutes)
| where LoginIP != ResetIP
| project ResetTime, LoginTime, MinutesBetween = datetime_diff('minute', LoginTime, ResetTime), TargetUpn, ResetActor, ResetIP, LoginIP, Country, City, DeviceName, AadDeviceId, UserAgent, AppDisplayName
| order by LoginTime desc
```

### MFA push-fatigue burst followed by approved sign-in from new device

`UC_7_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count(eval('Authentication.action'="failure")) as fail_count, min(_time) as first_fail, max(_time) as last_fail from datamodel=Authentication.Authentication where Authentication.app IN ("AzureActiveDirectory","AAD","Office365") AND Authentication.signature IN ("MFA challenge denied","500121","50158","50140","500133") by Authentication.user, _time span=15m | rename Authentication.user as user | where fail_count >= 5 | join type=inner user [| tstats summariesonly=true min(_time) as success_time, values(Authentication.src) as success_src from datamodel=Authentication.Authentication where Authentication.action="success" AND Authentication.app IN ("AzureActiveDirectory","AAD","Office365") by Authentication.user | rename Authentication.user as user] | where success_time >= first_fail AND success_time <= (last_fail + 600) | table first_fail, last_fail, fail_count, success_time, user, success_src | sort - success_time
```

**Defender KQL:**
```kql
let WindowMinutes = 15m;
let FatigueBursts = AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode in (500121, 50158, 50140, 500133)
| summarize DenialCount = count(), DistinctIPs = dcount(IPAddress), FirstDenial = min(Timestamp), LastDenial = max(Timestamp), SampleErrors = make_set(ErrorCode, 10), SampleIPs = make_set(IPAddress, 10) by AccountUpn, AccountObjectId, bin(Timestamp, WindowMinutes)
| where DenialCount >= 5;
FatigueBursts
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | project SuccessTime = Timestamp, AccountUpn, SuccessIP = IPAddress, SuccessCountry = Country, SuccessCity = City, SuccessDevice = DeviceName, SuccessUA = UserAgent, SuccessApp = AppDisplayName, AuthDetails = AuthenticationDetails
) on AccountUpn
| where SuccessTime between (FirstDenial .. LastDenial + 10m)
| project AccountUpn, FirstDenial, LastDenial, DenialCount, DistinctIPs, SampleErrors, SampleIPs, SuccessTime, SuccessIP, SuccessCountry, SuccessCity, SuccessDevice, SuccessUA, SuccessApp
| order by SuccessTime desc
```

### Privileged role assignment within 60 minutes of a user's first interactive sign-in from new IP

`UC_7_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as first_login, values(Authentication.src) as first_src from datamodel=Authentication.Authentication where Authentication.action="success" AND Authentication.app IN ("AzureActiveDirectory","AAD") by Authentication.user | rename Authentication.user as target_user | join type=inner target_user [| tstats summariesonly=true min(_time) as escalation_time, values(All_Changes.command) as role_action, values(All_Changes.user) as actor from datamodel=Change.All_Changes where All_Changes.action="created" AND All_Changes.object_category="role" AND (All_Changes.command IN ("Add member to role","Add eligible member to role","Add member to role in PIM completed (permanent)")) by All_Changes.object | rename All_Changes.object as target_user] | where escalation_time >= first_login AND (escalation_time - first_login) <= 3600 | eval minutes_to_escalation = round((escalation_time-first_login)/60,1) | table first_login, escalation_time, minutes_to_escalation, target_user, role_action, actor, first_src | sort - escalation_time
```

**Defender KQL:**
```kql
let WindowMinutes = 60m;
let FirstLogins = AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| summarize FirstLogin = min(Timestamp), arg_min(Timestamp, IPAddress, Country, City, DeviceName) by AccountUpn, AccountObjectId;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Entra ID" or Application == "Office 365"
| where ActionType in ("Add member to role.","Add eligible member to role.","Add member to role in PIM completed (permanent).","Add owner to application.","Add role assignment to role-assignable group.")
| extend TargetUpn = tostring(ActivityObjects[1].Name)
| where isnotempty(TargetUpn)
| join kind=inner FirstLogins on $left.TargetUpn == $right.AccountUpn
| where Timestamp between (FirstLogin .. FirstLogin + WindowMinutes)
| project EscalationTime = Timestamp, FirstLogin, MinutesSinceLogin = datetime_diff('minute', Timestamp, FirstLogin), TargetUpn, ActionType, ActivityObjects, Actor = AccountDisplayName, ActorIP = IPAddress, LoginIP = IPAddress1, LoginCountry = Country, LoginDevice = DeviceName
| order by EscalationTime desc
```

### Azure VM created in unfamiliar region by recently-elevated admin

`UC_7_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true earliest(_time) as escalation_time from datamodel=Change.All_Changes where All_Changes.action="created" AND All_Changes.object_category="role" AND All_Changes.command IN ("Add member to role","Add eligible member to role") by All_Changes.object | rename All_Changes.object as caller_upn | join type=inner caller_upn [| tstats summariesonly=true count, values(All_Changes.dest) as vm_resource, values(All_Changes.src) as caller_ip from datamodel=Change.All_Changes where All_Changes.action="created" AND All_Changes.object_category="compute" AND All_Changes.command="Microsoft.Compute/virtualMachines/write" by _time span=1h, All_Changes.user | rename All_Changes.user as caller_upn] | where _time >= escalation_time AND (_time - escalation_time) <= 172800 | eval hours_since_escalation = round((_time-escalation_time)/3600,1) | table _time, escalation_time, hours_since_escalation, caller_upn, vm_resource, caller_ip | sort - _time
```

### Bulk file staging via Rclone/WinRAR/7-Zip preceding outbound transfer to cloud storage

`UC_7_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as stage_time, values(Processes.process) as stage_cmd, values(Processes.process_name) as stage_bin from datamodel=Endpoint.Processes where (Processes.process_name IN ("rclone.exe","winrar.exe","rar.exe","7z.exe","7za.exe","winscp.com","winscp.exe") OR Processes.process IN ("*rclone copy *","*rclone sync *","*rclone mount *","*7z a *","*rar a -hp*","*winscp /command*")) AND Processes.user!="SYSTEM" by Processes.dest, Processes.user, _time span=10m | rename Processes.* as * | join type=inner dest [| tstats summariesonly=true min(_time) as net_time, values(All_Traffic.dest) as remote_dest, values(All_Traffic.dest_port) as remote_port, values(All_Traffic.app) as net_app from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_category="external" AND (All_Traffic.app IN ("rclone.exe","winscp.exe","curl.exe","powershell.exe") OR All_Traffic.dest_url IN ("*mega.nz*","*mega.io*","*backblazeb2.com*","*s3.amazonaws.com*","*wasabisys.com*","*storage.googleapis.com*","*pcloud.com*")) by All_Traffic.src, _time span=10m | rename All_Traffic.src as dest] | where net_time >= stage_time AND (net_time - stage_time) <= 1800 | table stage_time, net_time, dest, user, stage_bin, stage_cmd, remote_dest, remote_port, net_app | sort - stage_time
```

**Defender KQL:**
```kql
let WindowMinutes = 30m;
let StagingTools = DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName in~ ("rclone.exe","winrar.exe","rar.exe","7z.exe","7za.exe","winscp.com","winscp.exe","megacmdserver.exe","megacopy.exe")) 
     or (ProcessCommandLine has_any ("rclone copy ","rclone sync ","rclone mount ","7z a "," -hp","winscp /command ","megaput"))
| project Timestamp, DeviceId, DeviceName, AccountName, FileName, ProcessCommandLine, ParentImage = InitiatingProcessFileName, IsRdpSpawn = tostring(AdditionalFields);
StagingTools
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteIPType == "Public"
    | where (InitiatingProcessFileName in~ ("rclone.exe","winscp.exe","winscp.com","curl.exe","powershell.exe","pwsh.exe","megacmdserver.exe")) 
         or (RemoteUrl has_any ("mega.nz","mega.io","backblazeb2.com","s3.amazonaws.com","wasabisys.com","storage.googleapis.com","pcloud.com","transfer.sh","anonfiles.com"))
    | project NetTime = Timestamp, DeviceId, RemoteIP, RemoteUrl, RemotePort, NetInitiator = InitiatingProcessFileName, NetCmd = InitiatingProcessCommandLine
) on DeviceId
| where NetTime between (Timestamp .. Timestamp + WindowMinutes)
| project Timestamp, NetTime, MinutesBetween = datetime_diff('minute', NetTime, Timestamp), DeviceName, AccountName, StagingBin = FileName, ProcessCommandLine, ParentImage, NetInitiator, NetCmd, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### Volume Shadow Copy deletion via vssadmin/WMIC/PowerShell/bcdedit (RansomHub pre-impact)

`UC_7_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.user!="SYSTEM" AND ((Processes.process_name="vssadmin.exe" AND Processes.process="*delete*shadows*") OR (Processes.process_name="wmic.exe" AND Processes.process="*shadowcopy*" AND Processes.process="*delete*") OR (Processes.process_name="wbadmin.exe" AND Processes.process="*delete*") OR (Processes.process_name="bcdedit.exe" AND (Processes.process="*recoveryenabled*no*" OR Processes.process="*bootstatuspolicy*ignoreallfailures*")) OR (Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*Win32_Shadowcopy*" OR Processes.process="*Get-WmiObject*Shadow*" OR Processes.process="*Remove-WmiObject*Shadow*"))) by _time, Processes.dest, Processes.user, Processes.process_name | rename Processes.* as * | sort - _time
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
   or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
   or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete" and ProcessCommandLine has_any ("catalog","systemstatebackup","backup"))
   or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no","recoveryenabled No","bootstatuspolicy ignoreallfailures"))
   or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Win32_Shadowcopy","Get-WmiObject Win32_Shadowcopy","Get-CimInstance Win32_ShadowCopy","Remove-WmiObject","Delete-ShadowCopy"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ParentImage = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine, ProcessIntegrityLevel
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


## Why this matters

Severity classified as **CRIT** based on: 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
