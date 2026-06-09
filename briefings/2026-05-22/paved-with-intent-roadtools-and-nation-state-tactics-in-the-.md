# [CRIT] Paved With Intent: ROADtools and Nation-State Tactics in the Cloud

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-05-22
**Article:** https://unit42.paloaltonetworks.com/roadtools-cloud-attacks/

## Threat Profile

Threat Research Center 
Threat Research 
Cloud Cybersecurity Research 
Cloud Cybersecurity Research 
Paved With Intent: ROADtools and Nation-State Tactics in the Cloud 
14 min read 
Related Products Cortex Cortex Cloud Cortex XDR Cortex XSIAM Unit 42 Cloud Security Assessment Unit 42 Incident Response 
By: Bill Batchelor 
Eyal Rafian 
Published: May 22, 2026 
Categories: Cloud Cybersecurity Research 
Threat Research 
Tags: Curious Serpens 
Entra ID 
Microsoft Azure 
Microsoft graph API 
Midnight…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

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
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1098.005** — Account Manipulation: Device Registration
- **T1550** — Use Alternate Authentication Material
- **T1566.002** — Phishing: Spearphishing Link
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1606.002** — Forge Web Credentials: SAML Tokens

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Curious Serpens / APT29 ROADtools-pattern: device registration immediately following non-interactive token acquisition

`UC_180_8` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.action=created All_Changes.object_category=device All_Changes.change_type=AAD All_Changes.src_user_type=user by All_Changes.user All_Changes.object All_Changes.src All_Changes.user_agent | `drop_dm_object_name("All_Changes")` | join type=inner user [| tstats `summariesonly` count from datamodel=Authentication where Authentication.signature="UserLoggedIn" Authentication.authentication_method!="interactiveLogin" by Authentication.user Authentication.src _time span=15m | `drop_dm_object_name("Authentication")` | rename _time as auth_time] | where lastTime - auth_time < 900 AND lastTime - auth_time >= 0 | table firstTime user object src user_agent auth_time
```

**Defender KQL:**
```kql
let DeviceReg = AuditLogs | where TimeGenerated > ago(7d) | where OperationName has_any ("Add registered owner to device", "Add registered users to device", "Add device") | extend TargetUpn = tostring(TargetResources[0].userPrincipalName) | extend ActorUpn = tostring(InitiatedBy.user.userPrincipalName) | extend ActorIp = tostring(InitiatedBy.user.ipAddress) | project RegTime = TimeGenerated, ActorUpn, ActorIp, OperationName, TargetResources; let TokenAuth = AADSignInEventsBeta | where Timestamp > ago(7d) | where IsInteractive == false | where ResourceDisplayName in ("Microsoft Graph", "Azure Active Directory Graph", "Windows Azure Active Directory") | where ApplicationId in ("1b730954-1685-4b74-9bfd-dac224a7b894", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "04b07795-8ddb-461a-bbee-02f9e1bf7b46") | project AuthTime = Timestamp, AccountUpn, IPAddress, UserAgent, ApplicationId, ClientAppUsed; DeviceReg | join kind=inner TokenAuth on $left.ActorUpn == $right.AccountUpn | where datetime_diff('minute', RegTime, AuthTime) between (0 .. 30) | where ActorIp != IPAddress | project RegTime, AuthTime, MinutesBetween = datetime_diff('minute', RegTime, AuthTime), ActorUpn, RegIp = ActorIp, TokenIp = IPAddress, UserAgent, ApplicationId, ClientAppUsed
```

### [LLM] UTA0355 device-code phishing: deviceCode auth flow with cross-IP token redemption

`UC_180_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.signature_id="DeviceCodeAuthentication" OR Authentication.app="Microsoft Authentication Broker" by Authentication.user Authentication.src Authentication.user_agent Authentication.app | `drop_dm_object_name("Authentication")` | stats values(src) as src_list dc(src) as src_count values(user_agent) as ua_list dc(user_agent) as ua_count min(firstTime) as code_issued max(lastTime) as token_redeemed by user | where src_count >= 2 | eval delta_sec = token_redeemed - code_issued | where delta_sec < 900
```

**Defender KQL:**
```kql
AADSignInEventsBeta | where Timestamp > ago(7d) | where AuthenticationProcessingDetails has "deviceCode" or AuthenticationDetails has "device code" or ClientAppUsed == "Authenticated SMTP" and Application has "device" | extend IsDeviceCode = AuthenticationProcessingDetails has "deviceCode" or AuthenticationDetails has_cs "Device Code" | where IsDeviceCode == true | summarize CodeIssued = min(Timestamp), TokenRedeemed = max(Timestamp), SrcIPs = make_set(IPAddress, 10), SrcCountries = make_set(Country, 10), UAs = make_set(UserAgent, 10), IPCount = dcount(IPAddress), CountryCount = dcount(Country), Apps = make_set(ResourceDisplayName, 10), ReqIds = make_set(RequestId, 10) by AccountUpn, bin(Timestamp, 15m) | where IPCount >= 2 or CountryCount >= 2 | project CodeIssued, TokenRedeemed, DeltaSec = datetime_diff('second', TokenRedeemed, CodeIssued), AccountUpn, SrcIPs, SrcCountries, UAs, Apps
```

### [LLM] ROADtools roadtx FOCI client-ID swap: refresh-token resource hop across MS Office FOCI app IDs

`UC_180_10` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` values(Authentication.app) as apps dc(Authentication.app) as app_count values(Authentication.dest) as resources dc(Authentication.dest) as resource_count values(Authentication.src) as src_ips values(Authentication.user_agent) as user_agents min(_time) as first max(_time) as last from datamodel=Authentication where Authentication.signature_id="UserLoggedIn" Authentication.authentication_method="refreshToken" by Authentication.user Authentication.session_id | `drop_dm_object_name("Authentication")` | where app_count >= 3 AND (last - first) < 600 | search apps IN ("Microsoft Azure CLI","Microsoft Azure PowerShell","Microsoft Office","Microsoft Teams","Microsoft Edge","OneDrive","Microsoft Authentication Broker","Microsoft Intune Company Portal","Microsoft Authenticator App")
```

**Defender KQL:**
```kql
let FociApps = dynamic(["1b730954-1685-4b74-9bfd-dac224a7b894", "d3590ed6-52b3-4102-aeff-aad2292ab01c", "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "26a7ee05-5602-4d76-a7ba-eae8b7b67941", "27922004-5251-4030-b22d-91ecd9a37ea4", "4813382a-8fa7-425e-ab75-3b753aab3abb", "ab9b8c07-8f02-4f72-87fa-80105867a763", "844cca35-0656-46ce-b636-13f48b0eecbd", "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", "af124e86-4e96-495a-b70a-90f90ab96707"]); AADSignInEventsBeta | where Timestamp > ago(7d) | where IsInteractive == false | where ApplicationId in (FociApps) | where AuthenticationProcessingDetails has "refreshToken" or AuthenticationDetails has "Previously satisfied" | summarize Apps = make_set(Application, 20), AppIds = make_set(ApplicationId, 20), AppCount = dcount(ApplicationId), Resources = make_set(ResourceDisplayName, 20), ResourceCount = dcount(ResourceDisplayName), SrcIPs = make_set(IPAddress, 10), UAs = make_set(UserAgent, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountUpn, bin(Timestamp, 10m) | where AppCount >= 3 | where datetime_diff('minute', LastSeen, FirstSeen) <= 10 | project FirstSeen, LastSeen, AccountUpn, AppCount, Apps, AppIds, Resources, SrcIPs, UAs
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


## Why this matters

Severity classified as **CRIT** based on: 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
