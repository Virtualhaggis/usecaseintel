# [CRIT] Tycoon2FA hijacks Microsoft 365 accounts via device-code phishing

**Source:** BleepingComputer
**Published:** 2026-05-17
**Article:** https://www.bleepingcomputer.com/news/security/tycoon2fa-hijacks-microsoft-365-accounts-via-device-code-phishing/

## Threat Profile

Tycoon2FA hijacks Microsoft 365 accounts via device-code phishing 
By Bill Toulas 
May 17, 2026
10:43 AM
0 
The Tycoon2FA phishing kit now supports device-code phishing attacks and abuses Trustifi click-tracking URLs to hijack Microsoft 365 accounts.
Despite an international law enforcement operation disrupting the Tycoon2FA phishing platform in March, the malicious operation was rebuilt on new infrastructure and quickly returned to regular activity levels.
Earlier this month, Abnormal Security …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `47.90.180.205`
- **IPv4 (defanged):** `47.252.11.99`
- **Domain (defanged):** `cookies.28gholland.workers.dev`
- **Domain (defanged):** `shivacrio.com`
- **Domain (defanged):** `fijothi.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.002** — Proxy: External Proxy
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Successful OAuth deviceCode grant via Microsoft Authentication Broker (Tycoon2FA device-code phishing)

`UC_26_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`azure_monitor_aad` SigninLogs AppId="29d9ed98-a469-4536-ade2-f981bc1d605e" ResultType=0 AuthenticationProtocol="deviceCode" | stats min(_time) as firstSeen, max(_time) as lastSeen, values(IPAddress) as src_ips, values(UserAgent) as user_agents, values(DeviceDetail.deviceId) as new_device_ids by UserPrincipalName, AppDisplayName | where mvcount(new_device_ids) > 0
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e"   // Microsoft Authentication Broker
| where ErrorCode == 0                                              // successful auth only
| where IsInteractive == false                                      // deviceCode flow is non-interactive on the auth'd side
| extend ProcDetails = tostring(AuthenticationProcessingDetails)
| where ProcDetails has "DeviceCode" or ProcDetails has "deviceCode"
| project Timestamp, AccountUpn, AccountDisplayName, IPAddress, Country, City,
          UserAgent, ClientAppUsed, ResourceDisplayName, AadDeviceId,
          DeviceTrustType, OSPlatform, ConditionalAccessStatus, RiskLevelDuringSignIn
| order by Timestamp desc
```

### [LLM] Tycoon2FA device-code phishing infrastructure callouts (eSentire IOC set)

`UC_26_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(All_Traffic.dest_ip) as dest_ips values(All_Traffic.dest_port) as dest_ports values(All_Traffic.app) as procs from datamodel=Network_Traffic where (All_Traffic.dest_ip IN ("47.90.180.205","47.252.11.99") OR All_Traffic.dest="cookies.28gholland.workers.dev" OR All_Traffic.dest="shivacrio.com" OR All_Traffic.dest="fijothi.com") by All_Traffic.src, All_Traffic.user, All_Traffic.dest | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
let Tycoon2FA_IPs = dynamic(["47.90.180.205","47.252.11.99"]);
let Tycoon2FA_Domains = dynamic(["cookies.28gholland.workers.dev","shivacrio.com","fijothi.com"]);
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteIP in (Tycoon2FA_IPs)
         or RemoteUrl has_any (Tycoon2FA_Domains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              RemoteIP, RemoteUrl, RemotePort,
              Process=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine;
let DnsHits = DeviceEvents
    | where Timestamp > ago(14d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tostring(parse_json(AdditionalFields).QueryName)
    | where Q in~ (Tycoon2FA_Domains)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
              RemoteIP="", RemoteUrl=Q, RemotePort=int(null),
              Process=InitiatingProcessFileName, Cmd=InitiatingProcessCommandLine;
union NetHits, DnsHits
| order by Timestamp desc
```

### [LLM] Trustifi click-tracker click followed by microsoft.com/devicelogin navigation

`UC_26_10` · phase: **delivery** · confidence: **Medium**

**Defender KQL:**
```kql
let WindowMin = 10m;
let TrustifiClicks = UrlClickEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | where Url has_any ("events.trustifi.com","trustifi-mail.com",".trustifi.com/","workers.dev")
    | project ClickTime = Timestamp, AccountUpn, ClickedUrl = Url, NetworkMessageId, IPAddress;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "microsoft.com/devicelogin" or RemoteUrl has "login.microsoftonline.com/common/oauth2/deviceauth"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","arc.exe")
| join kind=inner TrustifiClicks on $left.InitiatingProcessAccountUpn == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + WindowMin)
| project ClickTime, NavTime = Timestamp,
          DelaySec = datetime_diff('second', Timestamp, ClickTime),
          DeviceName, AccountUpn, ClickedUrl, MS_Url = RemoteUrl,
          Browser = InitiatingProcessFileName
| order by ClickTime desc
```

### [LLM] Entra ID sign-in from Node.js / non-browser user agent

`UC_26_11` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`azure_monitor_aad` (SigninLogs OR AADNonInteractiveUserSignInLogs) ResultType=0 (UserAgent="*node-fetch*" OR UserAgent="*Node.js*" OR UserAgent="*axios*" OR UserAgent="*python-requests*" OR UserAgent="*MSAL*Python*") | stats min(_time) as firstSeen, max(_time) as lastSeen, values(IPAddress) as src_ips, values(AppDisplayName) as apps, values(UserAgent) as user_agents by UserPrincipalName
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where UserAgent matches regex @"(?i)\b(node-fetch|node\.js|axios|got/|undici)\b"
   or (ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e" and UserAgent !has "Mozilla" and isnotempty(UserAgent))
| project Timestamp, AccountUpn, AccountDisplayName, ApplicationId, AppDisplayName,
          ResourceDisplayName, IPAddress, Country, City, UserAgent, ClientAppUsed,
          IsInteractive, ConditionalAccessStatus, RiskLevelDuringSignIn
| order by Timestamp desc
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

### Article-specific behavioural hunt — Tycoon2FA hijacks Microsoft 365 accounts via device-code phishing

`UC_26_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Tycoon2FA hijacks Microsoft 365 accounts via device-code phishing ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Tycoon2FA hijacks Microsoft 365 accounts via device-code phishing
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `47.90.180.205`, `47.252.11.99`, `cookies.28gholland.workers.dev`, `shivacrio.com`, `fijothi.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
