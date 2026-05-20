# [HIGH] How Storm-2949 turned a compromised identity into a cloud-wide breach

**Source:** Microsoft Security Blog
**Published:** 2026-05-18
**Article:** https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/

## Threat Profile

Tags 
Credential theft 
Incident Response 
Content types 
Research 
Products and services 
Microsoft Defender 
Topics 
Actionable threat insights 
Microsoft Threat Intelligence recently uncovered a methodical, sophisticated, and multi-layered attack, where a threat actor we track as Storm-2949 launched a relentless campaign with a singular focus: to exfiltrate as much sensitive data from a target organization’s high-value assets as possible. The attack exfiltrated data from Microsoft 365 applica…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `176.123.4.44`
- **IPv4 (defanged):** `91.208.197.87`
- **IPv4 (defanged):** `185.241.208.243`

## MITRE ATT&CK Techniques

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration
- **T1087.004** — Account Discovery: Cloud Account
- **T1069.003** — Permission Groups Discovery: Cloud Groups
- **T1526** — Cloud Service Discovery
- **T1530** — Data from Cloud Storage
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1651** — Cloud Administration Command
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1555.006** — Credentials from Password Stores: Cloud Secrets Management
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1098.003** — Account Manipulation: Additional Cloud Roles

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Sign-in from Storm-2949 attacker infrastructure (176.123.4.44, 91.208.197.87, 185.241.208.243)

`UC_9_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.app) as app values(Authentication.src) as src_ip values(Authentication.dest) as dest from datamodel=Authentication where Authentication.action=success Authentication.src IN ("176.123.4.44","91.208.197.87","185.241.208.243") by Authentication.user | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union AADSignInEventsBeta, IdentityLogonEvents
| where Timestamp > ago(30d)
| where IPAddress in ("176.123.4.44","91.208.197.87","185.241.208.243")
| project Timestamp, IPAddress, AccountUpn, AccountDisplayName, Application, ResourceDisplayName, Country, UserAgent, ErrorCode, IsInteractive
| order by Timestamp desc
```

### [LLM] Self-service MFA method removal followed by attacker-device registration

`UC_9_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_audit` operationName IN ("Delete authentication method","Register security info","User registered security info","Update user","Reset user password") | bin _time span=15m | stats values(operationName) as ops dc(operationName) as opCount min(_time) as firstSeen max(_time) as lastSeen by targetUserPrincipalName initiatedBy_userPrincipalName initiatedBy_ipAddress _time | where opCount>=2 AND mvfind(ops,"Delete authentication method")>=0 AND mvfind(ops,"Register security info")>=0 | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application == "Microsoft Azure" or Application has "Azure Active Directory"
| where ActionType in ("Delete authentication method.","Register security info","User registered security info","Update user.","Reset user password.","Update authentication phone.")
| extend TargetUser = tostring(ActivityObjects[0].Name)
| summarize Ops = make_set(ActionType), OpCount = dcount(ActionType), IPs = make_set(IPAddress), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by TargetUser, AccountObjectId, bin(Timestamp, 15m)
| where OpCount >= 2 and Ops has "Delete authentication method." and Ops has_any ("Register security info","User registered security info")
| order by LastSeen desc
```

### [LLM] Microsoft Graph API user/SP enumeration via curl or python user-agent

`UC_9_14` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`azure_signin_noninteractive` AppDisplayName="Microsoft Graph*" UserAgent IN ("curl/*","python-requests/*","PostmanRuntime/*","axios/*","Go-http-client/*") | bin _time span=10m | stats count dc(ResourceDisplayName) as resourceCount values(IPAddress) as ips by UserPrincipalName UserAgent _time | where count > 30
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ApplicationId == "00000003-0000-0000-c000-000000000000" or Application has "Microsoft Graph"
| where UserAgent has_any ("curl/","python-requests/","python/","PostmanRuntime","axios/","Go-http-client","PowerShell/")
| where ActionType has_any ("List users","List applications","List servicePrincipals","List groups","Read user.","Read directoryObjects")
| summarize CallCount = count(), Activities = make_set(ActionType, 25), IPs = make_set(IPAddress, 10), UserAgents = make_set(UserAgent, 5) by AccountObjectId, AccountDisplayName, bin(Timestamp, 10m)
| where CallCount > 30
| order by CallCount desc
```

### [LLM] Mass OneDrive/SharePoint file download from single session

`UC_9_15` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`office365_management` Operation IN ("FileDownloaded","FileSyncDownloadedFull") Workload IN ("OneDrive","SharePoint") | bin _time span=10m | stats count dc(ObjectId) as uniqueFiles values(ClientIP) as src_ip values(UserAgent) as ua by UserId _time | where count > 200 OR uniqueFiles > 200 | sort - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft OneDrive for Business","Microsoft SharePoint Online")
| where ActionType in ("FileDownloaded","FileSyncDownloadedFull")
| summarize FileCount = count(), UniqueFiles = dcount(ObjectName), IPs = make_set(IPAddress, 10), UA = make_set(UserAgent, 5), FirstFile = min(Timestamp), LastFile = max(Timestamp) by AccountObjectId, AccountDisplayName, bin(Timestamp, 10m)
| where FileCount > 200 or UniqueFiles > 200
| extend DurationSec = datetime_diff("second", LastFile, FirstFile), HighRiskIP = iif(IPs has_any ("176.123.4.44","91.208.197.87","185.241.208.243"), "YES", "no")
| order by FileCount desc
```

### [LLM] Azure VM Run Command invocation from compromised cloud identity

`UC_9_16` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_activity` operationNameValue IN ("Microsoft.Compute/virtualMachines/runCommand/action","Microsoft.Compute/virtualMachines/runCommands/write","Microsoft.Compute/virtualMachines/extensions/write") | stats count values(ResourceId) as targetVMs values(CallerIpAddress) as src_ip by Caller _time | where count >= 1
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application == "Microsoft Azure"
| where ActionType has_any ("Microsoft.Compute/virtualMachines/runCommand/action","Microsoft.Compute/virtualMachines/runCommands/write","Run Command on Virtual Machine")
| extend TargetVM = tostring(ActivityObjects[0].Name)
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, ActionType, TargetVM, RawEventData, UserAgent
| order by Timestamp desc
```

### [LLM] ScreenConnect connectivity to Storm-2949 C2 (185.241.208.243)

`UC_9_17` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest="185.241.208.243" by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)`
| append [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name IN ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe","ScreenConnect.ClientSetup.exe") OR Processes.process IN ("*ScreenConnect*&h=185.241.208.243*","*ScreenConnect*&e=Access*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)`]
```

**Defender KQL:**
```kql
let ScreenConnectIP = "185.241.208.243";
let NetEvents = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIP == ScreenConnectIP
    | project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl;
let ProcEvents = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName has_any ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe","ScreenConnect.ClientSetup.exe")
       or ProcessCommandLine has_all ("ScreenConnect","185.241.208.243")
    | project Timestamp, DeviceName, DeviceId, FileName, ProcessCommandLine, AccountName, SHA256, InitiatingProcessFileName;
union NetEvents, ProcEvents
| order by Timestamp desc
```

### [LLM] Burst access to Azure Key Vault secrets from a single principal

`UC_9_18` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_keyvault` OperationName IN ("SecretGet","SecretList","KeyGet","KeyList","CertificateGet","VaultGet") | bin _time span=15m | stats dc(Resource) as secretsAccessed values(OperationName) as ops values(CallerIPAddress) as src_ip by identity_claim_upn _time | where secretsAccessed > 5
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "Key Vault" or ActionType has_any ("SecretGet","SecretList","KeyGet","KeyList","CertificateGet")
| extend Vault = tostring(ActivityObjects[0].Name)
| summarize SecretsAccessed = dcount(ObjectName), Ops = make_set(ActionType), Vaults = make_set(Vault), IPs = make_set(IPAddress) by AccountObjectId, AccountDisplayName, bin(Timestamp, 15m)
| where SecretsAccessed > 5
| extend HighRiskIP = iif(IPs has_any ("176.123.4.44","91.208.197.87","185.241.208.243"), "YES", "no")
| order by SecretsAccessed desc
```

### [LLM] Service principal credential addition or owner assignment

`UC_9_19` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_audit` operationName IN ("Add service principal credentials","Update application – Certificates and secrets management","Update service principal","Add owner to service principal","Add owner to application") | stats values(operationName) as ops values(targetResources_displayName) as targetSP values(initiatedBy_ipAddress) as src_ip values(result) as result by initiatedBy_userPrincipalName _time
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("Add service principal credentials.","Update application – Certificates and secrets management.","Update service principal.","Add owner to service principal.","Add owner to application.","Add application.")
| extend TargetSP = tostring(ActivityObjects[0].Name), TargetType = tostring(ActivityObjects[0].Type)
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, ActionType, TargetSP, TargetType, RawEventData
| order by Timestamp desc
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

### Fake CAPTCHA / clipboard-injected PowerShell (ClickFix / FakeCaptcha)

`UC_FAKECAPTCHA` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("explorer.exe","RuntimeBroker.exe")
      AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe")
      AND (Processes.process="*iex*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*FromBase64*" OR Processes.process="*DownloadString*"
        OR Processes.process="*hxxp*" OR Processes.process="*curl*" OR Processes.process="*wget*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `176.123.4.44`, `91.208.197.87`, `185.241.208.243`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 20 use case(s) fired, 35 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
