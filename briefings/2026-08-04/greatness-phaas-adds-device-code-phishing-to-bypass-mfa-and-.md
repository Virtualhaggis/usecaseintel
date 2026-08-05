# [CRIT] Greatness PhaaS Adds Device Code Phishing to Bypass MFA and Steal Tokens

**Source:** The Hacker News
**Published:** 2026-08-04
**Article:** https://thehackernews.com/2026/08/greatness-phaas-adds-device-code.html

## Threat Profile

Greatness PhaaS Adds Device Code Phishing to Bypass MFA and Steal Tokens 
 Ravie Lakshmanan  Aug 04, 2026 Phishing / Cybercrime 
The commercial phishing-as-a-service (PhaaS) toolkit known as Greatness has become the latest crimeware solution to add support for device code phishing, a rapidly growing cyber threat that abuses the legitimate OAuth 2.0 Device Authorization Grant to bypass Multi-Factor Authentication (MFA) and seize control of user accounts.
"Greatness supports AiTM [adversary-in-t…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `38.248.95.214`
- **Domain (defanged):** `hashmashryshl.cfd`
- **Domain (defanged):** `hashmashryly.cfd`
- **Domain (defanged):** `onlineyoutlook.one`
- **Domain (defanged):** `addtorimez.gba`
- **Domain (defanged):** `willgranttblesssecondflier.cfd`
- **Domain (defanged):** `lookatcreatilcense.one`
- **Domain (defanged):** `pleasebeatwithlllocliad.gbs`
- **Domain (defanged):** `wbajp.feelingfor.com`

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1621** — Multi-Factor Authentication Request Generation
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1098.005** — Account Manipulation: Device Registration
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1566.002** — Phishing: Spearphishing Link
- **T1656** — Impersonation
- **T1598.003** — Phishing for Information: Spearphishing Link
- **T1526** — Cloud Service Discovery
- **T1087.004** — Account Discovery: Cloud Account

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Entra ID device-code flow authentication (Greatness device-code phishing redemption)

`UC_37_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action="success" Authentication.authentication_method="deviceCode" by Authentication.user Authentication.src Authentication.app Authentication.dest
| `drop_dm_object_name(Authentication)`
| where count > 0
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where AuthenticationProcessingDetails has "Device Code"
| where ErrorCode == 0
| where AccountUpn !endswith "$"
| project Timestamp, AccountUpn, IPAddress, Country, City, Application, AppDisplayName, ResourceDisplayName, ClientAppUsed, UserAgent, DeviceTrustType, IsInteractive
| order by Timestamp desc
```

### M365 authentication from known Greatness AiTM proxy IP 38.248.95.214

`UC_37_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.src="38.248.95.214" by Authentication.user Authentication.app Authentication.src Authentication.action
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where IPAddress == "38.248.95.214"
| project Timestamp, AccountUpn, IPAddress, Country, Application, AppDisplayName, ResourceDisplayName, ClientAppUsed, UserAgent, ErrorCode, ConditionalAccessStatus
| order by Timestamp desc
```

### New device registration / PRT generation minutes after a device-code sign-in

`UC_37_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action="success" Authentication.authentication_method="deviceCode" by Authentication.user Authentication.src _time
| `drop_dm_object_name(Authentication)`
| rename user as signin_user, _time as signin_time
| join type=inner signin_user [ search index=azuread (operationName="Add registered device" OR operationName="Register device" OR operationName="Add device") | rename properties.targetResources{}.userPrincipalName as signin_user, _time as reg_time ]
| eval delay_min=round((reg_time-signin_time)/60,1)
| where delay_min>=0 AND delay_min<=60
| table signin_time reg_time delay_min signin_user src
```

### Malicious inbox rule created hours after anomalous M365 sign-in

`UC_37_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action="success" Authentication.authentication_method="deviceCode" by Authentication.user _time
| `drop_dm_object_name(Authentication)`
| rename user as rule_user, _time as signin_time
| join type=inner rule_user [ search index=o365 Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules") (Parameters="*ForwardTo*" OR Parameters="*RedirectTo*" OR Parameters="*Delete*" OR Parameters="*Junk*") | rename UserId as rule_user, _time as rule_time ]
| eval delay_hr=round((rule_time-signin_time)/3600,1)
| where delay_hr>=0 AND delay_hr<=24
| table signin_time rule_time delay_hr rule_user Operation Parameters
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where RawEventData has_any ("ForwardTo", "RedirectTo", "DeleteMessage", "MoveToFolder", "Junk", "Deleted Items")
| project Timestamp, AccountDisplayName, AccountId, IPAddress, ActionType, ObjectName, UserAgent, RawEventData
| order by Timestamp desc
```

### RingCentral voicemail phishing lure delivered despite SPF/DKIM/DMARC failure (safe-sender bypass)

`UC_37_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Email where All_Email.direction="inbound" (All_Email.subject="*voicemail*" OR All_Email.subject="*voice message*" OR All_Email.subject="*RingCentral*") by All_Email.src_user All_Email.recipient All_Email.subject All_Email.message_id
| `drop_dm_object_name(All_Email)`
| sort - count
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(14d)
| where EmailDirection == "Inbound"
| where DeliveryAction == "Delivered" and DeliveryLocation == "Inbox"
| where SenderFromDomain has "ringcentral" or SenderDisplayName has "RingCentral" or Subject has_any ("voicemail", "voice message", "new voice")
| where AuthenticationDetails has "fail"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromDomain, SenderDisplayName, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, AuthenticationDetails
| order by Timestamp desc
```

### Navigation / DNS to Greatness PhaaS phishing infrastructure domains

`UC_37_12` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where nodename=DNS DNS.query IN ("hashmashryshl.cfd","hashmashryly.cfd","onlineyoutlook.one","willgranttblesssecondflier.cfd","lookatcreatilcense.one","wbajp.feelingfor.com","addtorimez.gba","pleasebeatwithlllocliad.gbs") by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
let iocDomains = dynamic(["hashmashryshl.cfd","hashmashryly.cfd","onlineyoutlook.one","willgranttblesssecondflier.cfd","lookatcreatilcense.one","wbajp.feelingfor.com","addtorimez.gba","pleasebeatwithlllocliad.gbs"]);
union
( DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl has_any (iocDomains) | project Timestamp, Source="Network", DeviceName, AccountName=InitiatingProcessAccountName, Indicator=RemoteUrl, InitiatingProcessFileName ),
( DeviceEvents | where Timestamp > ago(30d) | where RemoteUrl has_any (iocDomains) | project Timestamp, Source="DeviceEvent", DeviceName, AccountName, Indicator=RemoteUrl, InitiatingProcessFileName )
| order by Timestamp desc
```

### Post-compromise Microsoft Graph enumeration across many M365 resources in minutes

`UC_37_13` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Authentication.dest) as ResourceCount values(Authentication.dest) as Resources min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action="success" by Authentication.user Authentication.src _time span=10m
| `drop_dm_object_name(Authentication)`
| where ResourceCount >= 5
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - ResourceCount
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where ErrorCode == 0
| where AccountUpn !endswith "$"
| summarize ResourceCount = dcount(ResourceDisplayName), Resources = make_set(ResourceDisplayName, 20), IPs = make_set(IPAddress, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountUpn, bin(Timestamp, 10m)
| where ResourceCount >= 5   // 5+ distinct M365 resources touched by one user in 10m = enumeration fan-out (baseline P95 ~= 3)
| where Resources has_any ("Office 365 Exchange Online", "Microsoft Teams", "Office 365 SharePoint Online", "Microsoft Graph", "OneDrive")
| order by ResourceCount desc
```

### Inbound email containing Microsoft device-code / devicelogin URL from external phishing context

`UC_37_14` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Email where All_Email.direction="inbound" (All_Email.url="*microsoft.com/devicelogin*" OR All_Email.url="*aka.ms/devicelogin*" OR All_Email.url="*oauth2/v2.0/devicecode*" OR All_Email.url="*oauth2/deviceauth*") by All_Email.src_user All_Email.recipient All_Email.subject All_Email.url
| `drop_dm_object_name(All_Email)`
| sort - count
```

**Defender KQL:**
```kql
let devUrls = dynamic(["microsoft.com/devicelogin","aka.ms/devicelogin","oauth2/v2.0/devicecode","oauth2/deviceauth"]);
EmailUrlInfo
| where Timestamp > ago(14d)
| where Url has_any (devUrls)
| join kind=inner ( EmailEvents | where Timestamp > ago(14d) | where EmailDirection == "Inbound" and DeliveryAction == "Delivered" | project NetworkMessageId, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject ) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, Url
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `38.248.95.214`, `hashmashryshl.cfd`, `hashmashryly.cfd`, `onlineyoutlook.one`, `addtorimez.gba`, `willgranttblesssecondflier.cfd`, `lookatcreatilcense.one`, `pleasebeatwithlllocliad.gbs` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
