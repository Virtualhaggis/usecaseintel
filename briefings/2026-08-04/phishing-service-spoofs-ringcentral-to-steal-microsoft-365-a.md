# [CRIT] Phishing service spoofs RingCentral to steal Microsoft 365 accounts

**Source:** BleepingComputer
**Published:** 2026-08-04
**Article:** https://www.bleepingcomputer.com/news/security/phishing-service-spoofs-ringcentral-to-steal-microsoft-365-accounts/

## Threat Profile

Phishing service spoofs RingCentral to steal Microsoft 365 accounts 
By Bill Toulas 
August 4, 2026
05:45 PM
0 
The Greatness phishing-as-a-service (PhaaS) platform has expanded from credential phishing to adversary-in-the-middle attacks and device-code phishing targeting Microsoft 365 accounts.
The platform has been active since at least mid-2022 , targeting Microsoft 365 users in the United States, Canada, the UK, Australia, and South Africa.
It evolved over the years and now targets multiple …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `38.248.95.214`
- **Domain (defanged):** `panel.securehubcloud.com`
- **Domain (defanged):** `aitomayu.com`

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
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1656** — Impersonation
- **T1557** — Adversary-in-the-Middle
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1539** — Steal Web Session Cookie
- **T1621** — Multi-Factor Authentication Request Generation
- **T1526** — Cloud Service Discovery
- **T1213** — Data from Information Repositories
- **T1087.004** — Account Discovery: Cloud Account
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Spoofed RingCentral email failing SPF/DMARC/DKIM but delivered to inbox via whitelist

`UC_8_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(14d)
| where EmailDirection == "Inbound"
| where SenderFromDomain =~ "ringcentral.com" or SenderDisplayName has "ringcentral"
| extend AuthDetails = tolower(tostring(AuthenticationDetails))
| where AuthDetails has "\"spf\":\"fail\"" or AuthDetails has "\"spf\":\"softfail\""
     or AuthDetails has "\"dmarc\":\"fail\"" or AuthDetails has "\"dkim\":\"none\""
| where DeliveryAction == "Delivered" and DeliveryLocation == "Inbox/folder"
| project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderFromDomain, SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, AuthenticationDetails
| order by Timestamp desc
```

### M365 sign-in from confirmed Greatness AiTM proxy IP 38.248.95.214

`UC_8_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action=success Authentication.src="38.248.95.214" by Authentication.user Authentication.app Authentication.src Authentication.signature
| `drop_dm_object_name(Authentication)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where IPAddress == "38.248.95.214"
| where ErrorCode == 0
| project Timestamp, AccountUpn, AccountDisplayName, IPAddress, Country, City, Application, ResourceDisplayName, ClientAppUsed, UserAgent, ConditionalAccessStatus, IsInteractive
| order by Timestamp desc
```

### OAuth 2.0 device-code authentication flow success (Greatness device-code phishing)

`UC_8_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where ErrorCode == 0
| where tostring(AuthenticationProcessingDetails) has "Device Code"
| where Application !in~ ("Microsoft Azure CLI","Microsoft Azure PowerShell")
| project Timestamp, AccountUpn, AccountDisplayName, IPAddress, Country, City, Application, ResourceDisplayName, ClientAppUsed, UserAgent, IsInteractive
| order by Timestamp desc
```

### M365 token replay: non-interactive sign-in from IP never used interactively by the user

`UC_8_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Authentication.src) as src_count values(Authentication.src) as src_list count from datamodel=Authentication where Authentication.action=success by Authentication.user
| `drop_dm_object_name(Authentication)`
| where src_count >= 3
```

**Defender KQL:**
```kql
let Lookback = 14d;
let InteractiveIPs = AADSignInEventsBeta
    | where Timestamp > ago(Lookback)
    | where IsInteractive == true and ErrorCode == 0
    | distinct AccountUpn, IPAddress;
AADSignInEventsBeta
| where Timestamp > ago(Lookback)
| where IsInteractive == false and ErrorCode == 0
| join kind=leftanti InteractiveIPs on AccountUpn, IPAddress
| summarize NonInteractiveSignins = count(), Apps = make_set(Application, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountUpn, IPAddress, Country
| where NonInteractiveSignins >= 1
| order by LastSeen desc
```

### Post-compromise Microsoft Graph multi-service enumeration from single session

`UC_8_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
let Window = 1h;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in~ ("Microsoft Graph","Office 365 Exchange Online","Microsoft SharePoint Online","Microsoft Teams","Microsoft OneDrive for Business")
     or ActionType has_any ("MailItemsAccessed","FileAccessed","FilePreviewed","FileDownloaded","SearchQueryInitiatedExchange","SearchQueryInitiatedSharePoint","MemberAdded")
| summarize DistinctActions = dcount(ActionType), Services = make_set(Application, 10), Actions = make_set(ActionType, 25), Events = count()
          by AccountObjectId, AccountDisplayName, IPAddress, ISP, bin(Timestamp, Window)
| where DistinctActions >= 5 and Events > 100    // broad cross-service access burst in 1h
| order by Events desc
```

### Endpoint/mail contact with confirmed Greatness C2 panel.securehubcloud.com or proxy 38.248.95.214

`UC_8_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*securehubcloud.com*" OR Web.dest="38.248.95.214" by Web.src Web.dest Web.url Web.user
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has_any ("panel.securehubcloud.com","securehubcloud.com") or RemoteIP == "38.248.95.214"
 | project Timestamp, Signal="Network", Entity=DeviceName, Who=InitiatingProcessAccountName, Detail=strcat(InitiatingProcessFileName, " -> ", RemoteUrl, " ", RemoteIP)),
(EmailUrlInfo
 | where Timestamp > ago(30d)
 | where Url has_any ("panel.securehubcloud.com","securehubcloud.com") or UrlDomain has "securehubcloud.com"
 | project Timestamp, Signal="EmailUrl", Entity=NetworkMessageId, Who="", Detail=Url)
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `38.248.95.214`, `panel.securehubcloud.com`, `aitomayu.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
