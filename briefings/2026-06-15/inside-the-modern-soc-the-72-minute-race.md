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
- **T1621** — Multi-Factor Authentication Request Generation
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556.006** — Modify Authentication Process: MFA
- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1578.002** — Modify Cloud Compute Infrastructure: Create Cloud Instance
- **T1578.004** — Modify Cloud Compute Infrastructure: Revert Cloud Instance
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1136.003** — Create Account: Cloud Account
- **T1567.002** — Exfiltration to Cloud Storage
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1070.001** — Indicator Removal: Clear Windows Event Logs
- **T1490** — Inhibit System Recovery
- **T1021.001** — Remote Services: RDP
- **T1021.006** — Remote Services: WinRM
- **T1550.002** — Use Alternate Authentication Material: Pass the Hash

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### MFA fatigue spam: ≥5 failed prompts followed by success approval from new device

`UC_1_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action=failure Authentication.signature_id IN ("50140","500121","50158") by Authentication.user _time span=10m | `drop_dm_object_name(Authentication)` | where count >= 5 | join type=inner user [| tstats `summariesonly` min(_time) as success_time from datamodel=Authentication where Authentication.action=success by Authentication.user | `drop_dm_object_name(Authentication)`] | where success_time > _time AND success_time < _time + 600
```

**Defender KQL:**
```kql
let Window = 10m;
let Failures = AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode in (50140, 500121, 50158)
| summarize FailureCount = count(), FailureIPs = make_set(IPAddress,5), FirstFail = min(Timestamp), LastFail = max(Timestamp) by AccountUpn, bin(Timestamp, Window)
| where FailureCount >= 5;
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0 and IsInteractive == true
| join kind=inner Failures on AccountUpn
| where Timestamp between (LastFail .. LastFail + 5m)
| project Timestamp, AccountUpn, IPAddress, Country, City, DeviceName, Application, FailureCount, FailureIPs, FirstFail, LastFail
```

### Help-desk-style password/MFA reset immediately followed by successful sign-in from new geo

`UC_1_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as reset_time from datamodel=Change where Change.action=modified Change.object_category=user Change.change_type IN ("password reset","mfa registered","strongAuthenticationPhoneAppDetail") by Change.src_user Change.user | `drop_dm_object_name(Change)` | rename user as target_user | join type=inner target_user [| tstats `summariesonly` min(_time) as login_time values(Authentication.src) as src_ip from datamodel=Authentication where Authentication.action=success by Authentication.user | `drop_dm_object_name(Authentication)` | rename user as target_user] | where login_time > reset_time AND login_time < reset_time + 1800
```

**Defender KQL:**
```kql
let Resets = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Reset user password","Update user","Update authentication methods of user","Admin registered security info","Admin updated security info","User registered security info")
| mv-expand TargetResources
| extend TargetUpn = tostring(TargetResources.userPrincipalName), Initiator = tostring(InitiatedBy.user.userPrincipalName)
| where isnotempty(TargetUpn) and TargetUpn != Initiator
| project ResetTime = TimeGenerated, TargetUpn, Initiator, OperationName;
Resets
| join kind=inner (SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0
    | project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, DeviceDetail
  ) on $left.TargetUpn == $right.UserPrincipalName
| where TimeGenerated between (ResetTime .. ResetTime + 30m)
| join kind=leftouter (IdentityInfo | summarize KnownCountries = make_set(Country) by AccountUpn) on $left.UserPrincipalName == $right.AccountUpn
| extend NewGeo = iff(Location !in (KnownCountries), true, false)
| where NewGeo == true
| project ResetTime, Initiator, UserPrincipalName, SigninTime = TimeGenerated, Location, IPAddress, AppDisplayName, DeviceDetail
```

### Privileged role assignment within 15 minutes of first-ever interactive sign-in by user

`UC_1_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as role_time values(Change.object) as role_assigned from datamodel=Change where Change.change_type="role assignment" by Change.user Change.src_user | `drop_dm_object_name(Change)` | rename user as actor | join type=inner actor [| tstats `summariesonly` min(_time) as first_login from datamodel=Authentication where Authentication.action=success by Authentication.user | `drop_dm_object_name(Authentication)` | rename user as actor] | where role_time < first_login + 900
```

**Defender KQL:**
```kql
let RoleOps = AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName in ("Add member to role","Add eligible member to role","Add member to role completed (PIM activation)","Add app role assignment to service principal","Add member to group")
| mv-expand TargetResources
| extend TargetUpn = tostring(TargetResources.userPrincipalName), Role = tostring(parse_json(tostring(TargetResources.modifiedProperties))[1].newValue), Initiator = tostring(InitiatedBy.user.userPrincipalName)
| where Role has_any ("Global Administrator","Privileged Role Administrator","User Administrator","Application Administrator","Cloud Application Administrator","Helpdesk Administrator","Privileged Authentication Administrator")
| project RoleTime = TimeGenerated, Initiator, TargetUpn, Role;
RoleOps
| join kind=inner (SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0 and IsInteractive == true
    | summarize FirstLogin = min(TimeGenerated), IPAddress = any(IPAddress), Location = any(Location) by UserPrincipalName) on $left.Initiator == $right.UserPrincipalName
| where RoleTime between (FirstLogin .. FirstLogin + 15m)
| project FirstLogin, RoleTime, MinutesAfterLogon = datetime_diff('minute', RoleTime, FirstLogin), Initiator, TargetUpn, Role, IPAddress, Location
```

### Rogue VM / virtual-disk provisioning followed by cross-tenant disk mount

`UC_1_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Change where Change.change_type="compute provision" by Change.user Change.src Change.object _time span=1h | `drop_dm_object_name(Change)` | join type=left user [| tstats `summariesonly` count as baseline_count from datamodel=Change where Change.change_type="compute provision" earliest=-30d@d latest=-1d@d by Change.user | `drop_dm_object_name(Change)` | rename count as baseline_count] | where isnull(baseline_count) OR baseline_count = 0
```

### New service principal / app registration granted broad consent within 1h of admin sign-in

`UC_1_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as create_time values(Change.object) as app_name from datamodel=Change where Change.change_type IN ("application created","service principal created") by Change.user | `drop_dm_object_name(Change)` | rename user as Initiator | join type=left Initiator [| tstats `summariesonly` min(_time) as consent_time values(Change.object) as scope from datamodel=Change where Change.change_type="oauth consent" by Change.user | `drop_dm_object_name(Change)` | rename user as Initiator] | where consent_time > create_time AND consent_time < create_time + 3600
```

**Defender KQL:**
```kql
let Risky = dynamic(["Mail.ReadWrite.All","Mail.Send","Mail.Send.All","Files.ReadWrite.All","Sites.FullControl.All","Directory.ReadWrite.All","Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","RoleManagement.ReadWrite.Directory","User.ReadWrite.All"]);
let AppCreate = CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Add application.","Add service principal.","Add owner to application.","Add owner to service principal.")
| extend Initiator = AccountDisplayName, AppName = tostring(parse_json(tostring(RawEventData)).Target[3].ID)
| project AppCreateTime = Timestamp, Initiator, AppName;
AppCreate
| join kind=inner (CloudAppEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("Consent to application.","Add app role assignment grant to user.","Add delegated permission grant.")
    | extend ConsentScope = tostring(parse_json(tostring(RawEventData)).ModifiedProperties)
    | where ConsentScope has_any (Risky)
    | project ConsentTime = Timestamp, ConsentInitiator = AccountDisplayName, ConsentScope, AppId = tostring(parse_json(tostring(RawEventData)).ObjectId)) on $left.Initiator == $right.ConsentInitiator
| where ConsentTime between (AppCreateTime .. AppCreateTime + 1h)
| project AppCreateTime, ConsentTime, Initiator, AppName, ConsentScope
```

### Sustained large-volume egress from VPN/RDP gateway host to cloud storage in <72min

`UC_1_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` sum(All_Traffic.bytes_out) as bytes_out values(All_Traffic.dest) as dests from datamodel=Network_Traffic where All_Traffic.dest_category="cloud_storage" OR All_Traffic.dest IN ("*.s3.amazonaws.com","*.blob.core.windows.net","*.storage.googleapis.com","mega.nz","transfer.sh","anonfiles.com","file.io") by All_Traffic.src _time span=1h | `drop_dm_object_name(All_Traffic)` | join type=left src [| tstats `summariesonly` avg(All_Traffic.bytes_out) as baseline from datamodel=Network_Traffic where All_Traffic.dest_category="cloud_storage" earliest=-7d@d latest=-1d@d by All_Traffic.src _time span=1h | `drop_dm_object_name(All_Traffic)` | stats avg(baseline) as baseline by src] | where bytes_out > 5368709120 AND (isnull(baseline) OR bytes_out > baseline * 10)
```

**Defender KQL:**
```kql
let CloudStorage = dynamic(["s3.amazonaws.com","blob.core.windows.net","storage.googleapis.com","mega.nz","transfer.sh","anonfiles.com","file.io","pcloud.com","backblazeb2.com","wasabisys.com","dropboxapi.com","box.com"]);
let Baseline = DeviceNetworkEvents
| where Timestamp between (ago(7d) .. ago(2h))
| where RemoteUrl has_any (CloudStorage)
| summarize BaselineHourlyBytes = avg(toreal(tostring(parse_json(tostring(AdditionalFields)).bytes_out))) by DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(2h)
| where RemoteUrl has_any (CloudStorage)
| extend BytesOut = toreal(tostring(parse_json(tostring(AdditionalFields)).bytes_out))
| summarize TotalBytes = sum(BytesOut), DistinctRemotes = dcount(RemoteUrl), Procs = make_set(InitiatingProcessFileName,8), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, bin(Timestamp, 1h)
| join kind=leftouter Baseline on DeviceName
| where TotalBytes > 5368709120 and (isnull(BaselineHourlyBytes) or TotalBytes > BaselineHourlyBytes * 10)
| project DeviceName, FirstSeen, LastSeen, TotalBytesGB = TotalBytes/1073741824.0, BaselineGB = BaselineHourlyBytes/1073741824.0, DistinctRemotes, Procs
```

### Pre-impact log clearing (wevtutil) and shadow-copy destruction within 72-min win

`UC_1_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as first_seen max(_time) as last_seen values(Processes.process) as cmd_samples from datamodel=Endpoint.Processes where (Processes.process_name="wevtutil.exe" Processes.process IN ("*cl *","* cl *","*clear-log*")) OR (Processes.process_name="vssadmin.exe" Processes.process="*delete shadows*") OR (Processes.process_name="wmic.exe" Processes.process="*shadowcopy*delete*") OR (Processes.process_name="wbadmin.exe" Processes.process IN ("*delete catalog*","*delete systemstatebackup*","*delete backup*")) OR (Processes.process_name="bcdedit.exe" Processes.process IN ("*recoveryenabled*no*","*bootstatuspolicy*ignoreallfailures*")) by Processes.dest Processes.user _time span=1h | `drop_dm_object_name(Processes)` | stats dc(eval(case(match(cmd_samples,"wevtutil"),"log", match(cmd_samples,"vssadmin|shadowcopy"),"shadow", match(cmd_samples,"wbadmin"),"backup", match(cmd_samples,"bcdedit"),"recovery"))) as DestructiveOpKinds values(cmd_samples) as cmd_samples by dest user _time | where DestructiveOpKinds >= 2
```

**Defender KQL:**
```kql
let Window = 1h;
let Destructive = DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| extend OpKind = case(
    FileName =~ "wevtutil.exe" and ProcessCommandLine has_any (" cl "," clear-log","/e:false"), "LogClear",
    FileName =~ "vssadmin.exe" and ProcessCommandLine has "delete shadows", "ShadowDelete",
    FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"), "ShadowDelete",
    FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has_any ("Get-WmiObject Win32_Shadowcopy","Remove-WmiObject Win32_Shadowcopy","Get-CimInstance Win32_Shadowcopy"), "ShadowDelete",
    FileName =~ "wbadmin.exe" and ProcessCommandLine has_any ("delete catalog","delete systemstatebackup","delete backup"), "BackupCatalogDelete",
    FileName =~ "bcdedit.exe" and (ProcessCommandLine has_all ("recoveryenabled","no") or ProcessCommandLine has_all ("bootstatuspolicy","ignoreallfailures")), "RecoveryDisable",
    "")
| where isnotempty(OpKind)
| project Timestamp, DeviceName, AccountName, OpKind, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
Destructive
| summarize DistinctOpKinds = dcount(OpKind), OpsSeen = make_set(OpKind), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Samples = make_set(ProcessCommandLine, 10), Parents = make_set(InitiatingProcessFileName, 5) by DeviceName, AccountName, bin(Timestamp, Window)
| where DistinctOpKinds >= 2
| extend WindowMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| project FirstSeen, LastSeen, WindowMinutes, DeviceName, AccountName, DistinctOpKinds, OpsSeen, Parents, Samples
```

### Cross-host lateral movement fan-out from a single newly-authed account within 60min

`UC_1_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as first_logon dc(Authentication.dest) as host_count values(Authentication.dest) as hosts values(Authentication.src) as sources from datamodel=Authentication where Authentication.action=success Authentication.authentication_method IN ("RemoteInteractive","Network","NetworkCleartext") by Authentication.user _time span=1h | `drop_dm_object_name(Authentication)` | where host_count >= 3 AND NOT match(user,"\$$")
```

**Defender KQL:**
```kql
let Window = 1h;
let FanOut = DeviceLogonEvents
| where Timestamp > ago(1d)
| where ActionType == "LogonSuccess"
| where LogonType in ("RemoteInteractive","Network","NetworkCleartext","Interactive")
| where AccountName !endswith "$" and AccountName !in~ ("system","local service","network service","anonymous logon")
| summarize HostCount = dcount(DeviceName), Hosts = make_set(DeviceName, 25), Sources = make_set(RemoteIP, 10), Protocols = make_set(LogonType), FirstLogon = min(Timestamp), LastLogon = max(Timestamp) by AccountName, AccountDomain, bin(Timestamp, Window)
| where HostCount >= 3;
FanOut
| join kind=leftouter (DeviceLogonEvents
    | where Timestamp between (ago(30d) .. ago(1d))
    | where ActionType == "LogonSuccess"
    | summarize BaselineHosts = dcount(DeviceName) by AccountName) on AccountName
| extend BaselineHosts = iff(isempty(BaselineHosts), 0, BaselineHosts)
| where HostCount > BaselineHosts * 2 or BaselineHosts == 0
| project FirstLogon, LastLogon, AccountName, AccountDomain, HostCount, BaselineHosts, Hosts, Sources, Protocols
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

Severity classified as **CRIT** based on: 13 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
