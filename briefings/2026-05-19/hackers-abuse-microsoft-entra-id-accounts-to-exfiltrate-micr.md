# [HIGH] Hackers Abuse Microsoft Entra ID Accounts to Exfiltrate Microsoft 365 and Azure Data

**Source:** Cyber Security News
**Published:** 2026-05-19
**Article:** https://cybersecuritynews.com/hackers-abuse-microsoft-entra-id-accounts/

## Threat Profile

Home Cyber Security News 
Hackers Abuse Microsoft Entra ID Accounts to Exfiltrate Microsoft 365 and Azure Data 
By Tushar Subhra Dutta 
May 19, 2026 




A threat actor known as Storm-2949 has launched a sophisticated, multi-layered cloud attack campaign targeting Microsoft Entra ID accounts to steal sensitive data from Microsoft 365 and Azure environments. 
The campaign was recently uncovered and has raised serious concerns about how modern attackers can abuse legitimate cloud features to c…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `176.123.4.44`
- **IPv4 (defanged):** `91.208.197.87`
- **IPv4 (defanged):** `185.241.208.243`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1555.006** — Credentials from Password Stores: Cloud Secrets Management Stores
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1530** — Data from Cloud Storage
- **T1562.007** — Impair Defenses: Disable or Modify Cloud Firewall
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1070.004** — Indicator Removal: File Deletion
- **T1190** — Exploit Public-Facing Application
- **T1136.003** — Create Account: Cloud Account
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1087.004** — Account Discovery: Cloud Account
- **T1119** — Automated Collection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Entra SSPR abuse — password reset followed by auth-method overwrite within short window (Storm-2949)

`UC_3_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as reset_time max(_time) as last_change_time values(All_Changes.command) as ops values(All_Changes.src) as src_ips dc(All_Changes.command) as op_kinds from datamodel=Change where (All_Changes.command="*Reset password*" OR All_Changes.command="*User registered security info*" OR All_Changes.command="*Delete authentication method*" OR All_Changes.command="*Add authentication method*" OR All_Changes.command="*Update authentication method*") All_Changes.object_category=user by All_Changes.user span=30m
| `drop_dm_object_name("All_Changes")`
| where op_kinds>=2 AND mvfind(ops,"Reset password")>=0 AND (mvfind(ops,"Delete authentication method")>=0 OR mvfind(ops,"User registered security info")>=0)
| eval window_minutes=round((last_change_time-reset_time)/60,1)
| where window_minutes<=30
```

**Defender KQL:**
```kql
let Window = 30m;
let Resets = CloudAppEvents
| where Timestamp > ago(7d)
| where Application in~ ("Microsoft Azure Active Directory","Microsoft Entra ID","Office 365")
| where ActionType has_any ("Reset user password","Reset password (self-service)","Change user password")
| extend TargetUpn = tostring(ActivityObjects[0].Name)
| project ResetTime = Timestamp, TargetUpn, ResetActor = AccountDisplayName, ResetIp = IPAddress, ResetReportId = ReportId;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in~ ("Microsoft Azure Active Directory","Microsoft Entra ID")
| where ActionType has_any ("User registered security info","Delete authentication method","Add authentication method","Update authentication method","Register device")
| extend TargetUpn = tostring(ActivityObjects[0].Name)
| join kind=inner Resets on TargetUpn
| where Timestamp between (ResetTime .. ResetTime + Window)
| extend DeltaMin = datetime_diff('minute', Timestamp, ResetTime)
| project ResetTime, AuthMethodChangeTime = Timestamp, TargetUpn, ActionType, ResetIp, ChangeIp = IPAddress, DeltaMin, ResetActor, ChangeActor = AccountDisplayName
| order by ResetTime desc
```

### [LLM] Storm-2949 Key Vault burst — 10+ secret reads from one principal within 5 minutes

`UC_3_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_keyvault_diagnostic`
| where OperationName IN ("SecretGet","SecretListVersions","SecretList")
| bin _time span=5m
| stats min(_time) as first_seen max(_time) as last_seen dc(id) as unique_secrets values(CallerIPAddress) as caller_ips values(identity_claim_appid_g) as app_ids count by _time identity_claim_upn ResourceId
| where unique_secrets>=10
| eval burst_seconds=round(last_seen-first_seen,0)
| where burst_seconds<=300
```

### [LLM] Storage account key-listing burst with concurrent network ACL relaxation by same Entra principal

`UC_3_12` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_activity`
| where (OperationNameValue="MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION" OR OperationNameValue="MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE")
| eval is_listkeys=if(OperationNameValue="MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",1,0), is_acl_change=if(match(_raw,"(?i)(networkAcls|publicNetworkAccess|defaultAction)"),1,0)
| bin _time span=30m
| stats min(_time) as first_seen max(_time) as last_seen sum(is_listkeys) as listkeys_count sum(is_acl_change) as acl_change_count values(ResourceId) as resources values(CallerIpAddress) as caller_ips by _time Caller
| where listkeys_count>=1 AND acl_change_count>=1
```

### [LLM] SQL server firewall rule added then deleted by same caller within 1 hour (track-covering)

`UC_3_13` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_activity`
| where OperationNameValue IN ("MICROSOFT.SQL/SERVERS/FIREWALLRULES/WRITE","MICROSOFT.SQL/SERVERS/FIREWALLRULES/DELETE")
| eval phase=case(OperationNameValue="MICROSOFT.SQL/SERVERS/FIREWALLRULES/WRITE","add",OperationNameValue="MICROSOFT.SQL/SERVERS/FIREWALLRULES/DELETE","delete")
| bin _time span=1h
| stats min(_time) as first_seen max(_time) as last_seen values(phase) as phases dc(phase) as phase_kinds values(ResourceId) as rules values(CallerIpAddress) as caller_ips count by _time Caller
| where phase_kinds=2
| eval lifetime_minutes=round((last_seen-first_seen)/60,1)
| where lifetime_minutes<=60
```

### [LLM] VMAccess extension write creating local admin (Storm-2949 Azure VM persistence)

`UC_3_14` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_activity`
| where OperationNameValue="MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE" AND ActivityStatusValue="Success"
| where match(_raw,"(?i)(VMAccessAgent|VMAccessForLinux|VMAccessExtension)")
| rex field=Properties "(?i)\"userName\"\s*:\s*\"(?<new_user>[^\"]+)\""
| stats min(_time) as first_seen values(CallerIpAddress) as caller_ips values(ResourceId) as vms values(new_user) as new_users count by Caller
| where isnotnull(new_users) OR count>=1
```

### [LLM] Defender Antivirus disable attempt followed by ScreenConnect install / connection to 185.241.208.243

`UC_3_15` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as first_seen max(_time) as last_seen values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents count from datamodel=Endpoint.Processes where (Processes.process IN ("*Set-MpPreference*DisableRealtimeMonitoring*","*Set-MpPreference*-Disable*","*MpCmdRun*RemoveDefinitions*","*sc*stop*WinDefend*","*sc*config*WinDefend*","*sc*delete*Sense*") OR Processes.process IN ("*ScreenConnect*","*ConnectWiseControl*","*scclient*")) by Processes.dest Processes.user span=30m
| `drop_dm_object_name("Processes")`
| eval has_av_disable=if(match(cmdlines,"(?i)(Set-MpPreference|MpCmdRun|sc\s+(stop|delete|config)\s+(WinDefend|Sense))"),1,0)
| eval has_screenconnect=if(match(cmdlines,"(?i)(ScreenConnect|ConnectWiseControl|scclient)"),1,0)
| where has_av_disable=1 AND has_screenconnect=1
| append [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest=185.241.208.243 by All_Traffic.src All_Traffic.user All_Traffic.app | `drop_dm_object_name("All_Traffic")`]
```

**Defender KQL:**
```kql
let Window = 30m;
let AvDisable = DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("Set-MpPreference","MpCmdRun","DisableRealtimeMonitoring","DisableBehaviorMonitoring","DisableIOAVProtection")
   or (FileName =~ "sc.exe" and ProcessCommandLine has_any ("stop WinDefend","config WinDefend","delete Sense","stop Sense"))
   or ProcessCommandLine has "Add-MpPreference -ExclusionPath"
| project AvTime = Timestamp, DeviceId, DeviceName, AvAccount = AccountName, AvCmd = ProcessCommandLine, AvImage = FolderPath;
let ScreenConnect = DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("ScreenConnect","ConnectWiseControl","scclient.exe") 
   or InitiatingProcessFileName has_any ("ScreenConnect","ConnectWiseControl")
   or FolderPath has_any (@"\ScreenConnect\",@"\ConnectWiseControl\")
   or ProcessCommandLine has_any ("ScreenConnect.ClientService","ConnectWiseControl");
let ScNet = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "185.241.208.243"
| project NetTime = Timestamp, DeviceId, DeviceName, RemoteIP, RemotePort, NetProc = InitiatingProcessFileName, NetCmd = InitiatingProcessCommandLine;
AvDisable
| join kind=inner (ScreenConnect | extend ScTime = Timestamp) on DeviceId
| where ScTime between (AvTime - Window .. AvTime + Window)
| extend DeltaMin = datetime_diff('minute', ScTime, AvTime)
| project AvTime, ScTime, DeltaMin, DeviceName, AvAccount, AvCmd, ScImage = FolderPath, ScCmd = ProcessCommandLine
| union (ScNet)
| order by coalesce(AvTime, NetTime) desc
```

### [LLM] Entra sign-in or Azure control-plane operation from Storm-2949 egress IPs (176.123.4.44 / 91.208.197.87 / 185.241.208.243)

`UC_3_16` · phase: **recon** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Authentication where Authentication.src IN ("176.123.4.44","91.208.197.87","185.241.208.243") AND Authentication.action="success" by Authentication.user Authentication.src Authentication.app Authentication.dest _time
| `drop_dm_object_name("Authentication")`
| append [| tstats summariesonly=true count from datamodel=Change where All_Changes.src IN ("176.123.4.44","91.208.197.87","185.241.208.243") by All_Changes.user All_Changes.src All_Changes.command All_Changes.object _time | `drop_dm_object_name("All_Changes")`]
| sort 0 _time
```

**Defender KQL:**
```kql
let Storm2949Ips = dynamic(["176.123.4.44","91.208.197.87","185.241.208.243"]);
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where IPAddress in (Storm2949Ips)
| project Timestamp, AccountUpn, AccountDisplayName, IPAddress, Country, Application, ResourceDisplayName, ClientAppUsed, UserAgent, ErrorCode, RiskLevelDuringSignIn
| union (
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (Storm2949Ips)
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountUpn
)
| union (
CloudAppEvents
| where Timestamp > ago(30d)
| where IPAddress in (Storm2949Ips)
| project Timestamp, Application, ActionType, AccountDisplayName, IPAddress, ObjectName, ActivityType
)
| order by Timestamp desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Infostealer — non-browser process accessing browser cookie/login DBs

`UC_BROWSER_STEALER` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Google\Chrome\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Google\Chrome\User Data\*\Cookies*"
        OR Filesystem.file_path="*\Microsoft\Edge\User Data\*\Login Data*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\logins.json*"
        OR Filesystem.file_path="*\Mozilla\Firefox\Profiles\*\cookies.sqlite*")
      AND NOT Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Google\Chrome\User Data\", @"\Microsoft\Edge\User Data\", @"\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
```

### Phishing-link click correlated to endpoint execution

`UC_PHISH_LINK` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Phishing-link click that drives endpoint execution within 60s ```
| tstats `summariesonly` earliest(_time) AS click_time
    from datamodel=Web
    where Web.action="allowed"
    by Web.src, Web.user, Web.dest, Web.url
| `drop_dm_object_name(Web)`
| rename user AS recipient, dest AS clicked_domain, url AS clicked_url
| join type=inner recipient
    [| tstats `summariesonly` count
         from datamodel=Email.All_Email
         where All_Email.action="delivered" AND All_Email.url!="-"
         by All_Email.recipient, All_Email.src_user, All_Email.url, All_Email.subject
     | `drop_dm_object_name(All_Email)`
     | rex field=url "https?://(?<email_domain>[^/]+)"
     | rename recipient AS recipient]
| join type=inner src
    [| tstats `summariesonly` earliest(_time) AS exec_time
         values(Processes.process) AS exec_cmd, values(Processes.process_name) AS exec_proc
         from datamodel=Endpoint.Processes
         where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe",
                                                   "outlook.exe","brave.exe","arc.exe")
           AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                                            "rundll32.exe","regsvr32.exe","wscript.exe",
                                            "cscript.exe","bitsadmin.exe","certutil.exe",
                                            "curl.exe","wget.exe")
         by Processes.dest, Processes.user
     | `drop_dm_object_name(Processes)`
     | rename dest AS src]
| eval delta_sec = exec_time - click_time
| where delta_sec >= 0 AND delta_sec <= 60
| table click_time, exec_time, delta_sec, recipient, src, src_user, subject,
        clicked_domain, clicked_url, exec_proc, exec_cmd
| sort - click_time
```

**Defender KQL:**
```kql
// Phishing-link click that drives endpoint execution within 60s.
// Far higher fidelity than "every clicked URL" — most legitimate clicks
// never spawn a non-browser child process, so the join eliminates the
// 99% of noise that makes a raw click query unactionable.
let LookbackDays = 7d;
let SuspectClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | join kind=inner (
        EmailEvents
        | where Timestamp > ago(LookbackDays)
        | where DeliveryAction == "Delivered"
        | where EmailDirection == "Inbound"
        | project NetworkMessageId, Subject, SenderFromAddress, SenderFromDomain,
                  RecipientEmailAddress, EmailTimestamp = Timestamp
      ) on NetworkMessageId
    | join kind=leftouter (
        EmailUrlInfo | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId, Url
    | project ClickTime = Timestamp, AccountUpn, IPAddress, Url, UrlDomain,
              Subject, SenderFromAddress, SenderFromDomain, RecipientEmailAddress,
              ActionType;
// Correlate to a non-browser child process spawned within 60 seconds on
// the recipient's device.
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe",
                                         "outlook.exe","brave.exe","arc.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
                        "rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe",
                        "bitsadmin.exe","certutil.exe","curl.exe","wget.exe")
| join kind=inner SuspectClicks on $left.AccountName == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + 60s)
| project ClickTime, ProcessTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountName, RecipientEmailAddress, SenderFromAddress,
          Subject, Url, UrlDomain, ActionType,
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by ClickTime desc
```

### Email attachment opened from external sender

`UC_PHISH_ATTACH` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count
    from datamodel=Email.All_Email
    where All_Email.file_name!="-"
    by All_Email.src_user, All_Email.recipient, All_Email.file_name, All_Email.subject
| rename All_Email.recipient as user
| join type=inner user
    [| tstats `summariesonly` count
        from datamodel=Endpoint.Processes
        where Processes.parent_process_name IN ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
          AND Processes.process_name IN ("cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")
        by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
     | rename Processes.user as user]
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let MalAttachments = EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where AccountName !endswith "$"
    | project NetworkMessageId, RecipientEmailAddress,
              AttachmentFileName = FileName, AttachmentSHA256 = SHA256;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe")
| join kind=inner MalAttachments on $left.AccountUpn == $right.RecipientEmailAddress
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, AttachmentFileName, AttachmentSHA256
```

### Office app spawning script/LOLBin child process

`UC_OFFICE_CHILD` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
      AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `176.123.4.44`, `91.208.197.87`, `185.241.208.243`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 17 use case(s) fired, 33 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
