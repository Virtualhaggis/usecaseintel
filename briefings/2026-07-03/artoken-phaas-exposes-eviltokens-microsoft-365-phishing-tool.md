# [HIGH] ARToken PhaaS exposes EvilTokens' Microsoft 365 phishing toolkit

**Source:** BleepingComputer
**Published:** 2026-07-03
**Article:** https://www.bleepingcomputer.com/news/security/artoken-phaas-exposes-eviltokens-microsoft-365-phishing-toolkit/

## Threat Profile

ARToken PhaaS exposes EvilTokens' Microsoft 365 phishing toolkit 
By Lawrence Abrams 
July 3, 2026
10:12 AM
0 
A new phishing-as-a-service (PhaaS) platform dubbed "ARToken" appears to operate as an affiliate of the EvilTokens phishing platform, giving researchers a glimpse into an extensive toolkit designed to compromise Microsoft 365.
Cisco Talos researchers discovered the platform while investigating phishing infrastructure used in an incident response engagement and identified a React-based m…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `dashboard-bl.pamconj.com`
- **Domain (defanged):** `spx.pamconj.com`
- **Domain (defanged):** `clear90489058903-document.workers.dev`
- **Domain (defanged):** `authdocspro.com`
- **Domain (defanged):** `backdoor-hub.com`
- **Domain (defanged):** `bumpgames.net`
- **Domain (defanged):** `carbatterygurgaon.com`
- **Domain (defanged):** `careldutoit-el.co.za`
- **Domain (defanged):** `docusend.networkssolutionmail.com`
- **Domain (defanged):** `eventcalender-schedule.com`
- **Domain (defanged):** `evobothub.org`
- **Domain (defanged):** `framebound.cloud`
- **Domain (defanged):** `infinitechai.org`
- **Domain (defanged):** `internalmemorecord.bxwancheng.com`
- **Domain (defanged):** `macmamo.com`
- **Domain (defanged):** `mirsanotolastik.com`
- **Domain (defanged):** `mirzanyapi.com`
- **Domain (defanged):** `newmobilepolojean.com`
- **Domain (defanged):** `notificationsmanagersec.com`
- **Domain (defanged):** `pelangiservice.com`
- **Domain (defanged):** `prcservis.com`
- **Domain (defanged):** `promanager.outboundciwidey.com`
- **Domain (defanged):** `serenitygovsupplys.com`
- **Domain (defanged):** `signaturerequired.thecoolcactus.com`
- **Domain (defanged):** `smstltle.net`
- **Domain (defanged):** `statushelper.aguasomos.com`
- **Domain (defanged):** `suctwocesonesstory.com`
- **Domain (defanged):** `update.youcreadio.cfd`
- **Domain (defanged):** `well.atlantaperlnatal.com`

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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1098.005** — Account Manipulation: Device Registration
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1213.002** — Data from Information Repositories: SharePoint
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ARToken/EvilTokens invoice-lure phishing email with device-code kit domains

`UC_40_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email.All_Email where All_Email.direction=inbound (All_Email.url="*authdocspro.com*" OR All_Email.url="*docusend.networkssolutionmail.com*" OR All_Email.url="*clear90489058903-document.workers.dev*" OR All_Email.url="*notificationsmanagersec.com*" OR All_Email.url="*eventcalender-schedule.com*" OR All_Email.url="*evobothub.org*" OR All_Email.url="*framebound.cloud*" OR All_Email.url="*infinitechai.org*" OR All_Email.url="*macmamo.com*" OR All_Email.url="*pelangiservice.com*" OR All_Email.url="*authdocspro*") by All_Email.src_user All_Email.recipient All_Email.subject All_Email.url | `drop_dm_object_name(All_Email)` | sort - lastTime
```

**Defender KQL:**
```kql
let ARTokenDomains = dynamic(["authdocspro.com","docusend.networkssolutionmail.com","clear90489058903-document.workers.dev","notificationsmanagersec.com","eventcalender-schedule.com","evobothub.org","framebound.cloud","infinitechai.org","macmamo.com","pelangiservice.com","backdoor-hub.com","bumpgames.net","carbatterygurgaon.com","careldutoit-el.co.za","mirsanotolastik.com","mirzanyapi.com","newmobilepolojean.com","internalmemorecord.bxwancheng.com","dashboard-bl.pamconj.com","spx.pamconj.com"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| join kind=inner (EmailUrlInfo | where Timestamp > ago(30d) | project NetworkMessageId, Url, UrlDomain) on NetworkMessageId
| where UrlDomain in~ (ARTokenDomains) or Url has_any (ARTokenDomains)
| project Timestamp, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryAction, DeliveryLocation, NetworkMessageId
| order by Timestamp desc
```

### Endpoint DNS/network contact to ARToken/EvilTokens phishing & C2 domains

`UC_40_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="*authdocspro.com" OR DNS.query="*docusend.networkssolutionmail.com" OR DNS.query="*clear90489058903-document.workers.dev" OR DNS.query="*notificationsmanagersec.com" OR DNS.query="*eventcalender-schedule.com" OR DNS.query="*evobothub.org" OR DNS.query="*framebound.cloud" OR DNS.query="*infinitechai.org" OR DNS.query="*pelangiservice.com" OR DNS.query="*dashboard-bl.pamconj.com" OR DNS.query="*spx.pamconj.com") by DNS.src DNS.query | `drop_dm_object_name(DNS)` | sort - lastTime
```

**Defender KQL:**
```kql
let ARTokenDomains = dynamic(["authdocspro.com","docusend.networkssolutionmail.com","clear90489058903-document.workers.dev","notificationsmanagersec.com","eventcalender-schedule.com","evobothub.org","framebound.cloud","infinitechai.org","macmamo.com","pelangiservice.com","backdoor-hub.com","bumpgames.net","carbatterygurgaon.com","careldutoit-el.co.za","mirsanotolastik.com","mirzanyapi.com","newmobilepolojean.com","internalmemorecord.bxwancheng.com","dashboard-bl.pamconj.com","spx.pamconj.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (ARTokenDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### First-seen Microsoft Authentication Broker sign-in (device-code PRT acquisition)

`UC_40_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication.Authentication where Authentication.app="Microsoft Authentication Broker" Authentication.action=success by Authentication.user Authentication.src Authentication.app | `drop_dm_object_name(Authentication)` | eval earliest_30d=relative_time(now(),"-30d@d"), recent=relative_time(now(),"-1d@d") | where firstTime>=recent | sort - firstTime
```

**Defender KQL:**
```kql
let LookbackBaseline = 30d;
let RecentWindow = 1d;
let Baseline = AADSignInEventsBeta
    | where Timestamp between (ago(LookbackBaseline) .. ago(RecentWindow))
    | where (ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e" or Application =~ "Microsoft Authentication Broker")
    | where ErrorCode == 0
    | distinct AccountUpn;
AADSignInEventsBeta
| where Timestamp > ago(RecentWindow)
| where (ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e" or Application =~ "Microsoft Authentication Broker")
| where ErrorCode == 0
| join kind=leftanti Baseline on AccountUpn
| project Timestamp, AccountUpn, Application, IPAddress, Country, City, ClientAppUsed, DeviceTrustType, ResourceDisplayName, IsInteractive
| order by Timestamp desc
```

### Entra ID device registration tied to device-code token abuse (PRT persistence)

`UC_40_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where (All_Changes.action=created OR All_Changes.command="Add registered device" OR All_Changes.command="Register device") All_Changes.object_category=device by All_Changes.user All_Changes.src All_Changes.object All_Changes.command | `drop_dm_object_name(All_Changes)` | sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application in~ ("Microsoft Entra", "Office 365", "Azure Active Directory")
| where ActionType in~ ("Add registered device", "Register device", "Add device")
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, IPAddress, ObjectName, CountryCode, ISP, UserAgent, Application
| order by Timestamp desc
```

### Malicious inbox rule that hides/deletes/forwards mail (BEC cover-tracks)

`UC_40_10` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where (All_Changes.command="New-InboxRule" OR All_Changes.command="Set-InboxRule" OR All_Changes.command="UpdateInboxRules") by All_Changes.user All_Changes.src All_Changes.command All_Changes.object | `drop_dm_object_name(Change)` | sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| where (RawEventData has "DeleteMessage" and RawEventData has "true")
    or RawEventData has_any ("Deleted Items", "RSS Feeds", "RSS Subscriptions", "Conversation History", "Archive", "Junk Email")
    or RawEventData has_any ("ForwardTo", "RedirectTo", "ForwardAsAttachmentTo")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, ISP, CountryCode, ActionType, RawEventData
| order by Timestamp desc
```

### Post-compromise SharePoint/OneDrive bulk-download fan-out from single actor

`UC_40_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(All_Changes.object) as FileCount min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where (All_Changes.command="FileDownloaded" OR All_Changes.command="FileSyncDownloadedFull") (All_Changes.object_category=SharePoint OR All_Changes.object_category=OneDrive) by All_Changes.user All_Changes.src _time span=1h | `drop_dm_object_name(Change)` | where FileCount > 50 | sort - FileCount
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in~ ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in~ ("FileDownloaded", "FileSyncDownloadedFull", "FileAccessed")
| summarize FileCount = dcount(ObjectId), SampleFiles = make_set(ObjectName, 25), StartTime = min(Timestamp), EndTime = max(Timestamp)
    by AccountObjectId, AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where FileCount > 50   // 50 = bulk-download fan-out threshold; tune to org P99 per-user hourly download volume
| order by FileCount desc
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
  - IP / domain IOC(s): `dashboard-bl.pamconj.com`, `spx.pamconj.com`, `clear90489058903-document.workers.dev`, `authdocspro.com`, `backdoor-hub.com`, `bumpgames.net`, `carbatterygurgaon.com`, `careldutoit-el.co.za` _(+21 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
