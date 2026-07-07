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


Cisco Talos researchers discovered the platform while investigating phishing infrastructure used in an incident response engagement and identified a React…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `dashboard-bl.pamconj.com`
- **Domain (defanged):** `spx.pamconj.com`
- **Domain (defanged):** `clear90489058903-document.workers.dev`
- **Domain (defanged):** `authdocspro.com`
- **Domain (defanged):** `backdoor-hub.com`
- **Domain (defanged):** `docusend.networkssolutionmail.com`
- **Domain (defanged):** `eventcalender-schedule.com`
- **Domain (defanged):** `evobothub.org`
- **Domain (defanged):** `framebound.cloud`
- **Domain (defanged):** `infinitechai.org`
- **Domain (defanged):** `internalmemorecord.bxwancheng.com`
- **Domain (defanged):** `mirsanotolastik.com`
- **Domain (defanged):** `mirzanyapi.com`
- **Domain (defanged):** `newmobilepolojean.com`
- **Domain (defanged):** `notificationsmanagersec.com`
- **Domain (defanged):** `promanager.outboundciwidey.com`
- **Domain (defanged):** `serenitygovsupplys.com`
- **Domain (defanged):** `signaturerequired.thecoolcactus.com`
- **Domain (defanged):** `statushelper.aguasomos.com`
- **Domain (defanged):** `suctwocesonesstory.com`
- **Domain (defanged):** `topbuysella.com`
- **Domain (defanged):** `update.youcreadio.cfd`
- **Domain (defanged):** `well.atlantaperlnatal.com`
- **Domain (defanged):** `youremplregroup.com`
- **Domain (defanged):** `adobe-lar.denise-chxhistory-com-s-account.workers.dev`
- **Domain (defanged):** `docusign-vs4.finance-zltnservices-org-s-account.workers.dev`
- **Domain (defanged):** `onedrive-au8.hayixa9795-pazard-com-s-account.workers.dev`
- **Domain (defanged):** `sharepoint-uo2.angela-warrconstructioninc-onmicrosoft-com-s-account.workers.dev`
- **Domain (defanged):** `page-voicemail-3i6.ucbqzm9-ucl-ac-uk-s-account.workers.dev`

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
- **T1621** — Multi-Factor Authentication Request Generation
- **T1098.005** — Account Manipulation: Device Registration
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1102** — Web Service
- **T1213.002** — Data from Information Repositories: SharePoint
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ARToken/EvilTokens invoice-lure phish delivered with look-alike SharePoint / Workers IOC URL

`UC_29_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email.All_Email where All_Email.direction="inbound" (All_Email.url="*pamconj.com*" OR All_Email.url="*-document.workers.dev*" OR All_Email.url="*-docviewer.workers.dev*" OR All_Email.url="*-onedrive.workers.dev*" OR All_Email.url="*-adobe2.workers.dev*" OR All_Email.url="*authdocspro.com*" OR All_Email.url="*backdoor-hub.com*" OR All_Email.url="*networkssolutionmail.com*" OR All_Email.url="*evobothub.org*" OR All_Email.url="*framebound.cloud*" OR All_Email.url="*infinitechai.org*" OR All_Email.url="*bxwancheng.com*" OR All_Email.url="*mirsanotolastik.com*" OR All_Email.url="*mirzanyapi.com*" OR All_Email.url="*newmobilepolojean.com*" OR All_Email.url="*notificationsmanagersec.com*" OR All_Email.url="*outboundciwidey.com*" OR All_Email.url="*serenitygovsupplys.com*" OR All_Email.url="*thecoolcactus.com*" OR All_Email.url="*aguasomos.com*" OR All_Email.url="*suctwocesonesstory.com*" OR All_Email.url="*eventcalender-schedule.com*") by All_Email.src_user All_Email.recipient All_Email.subject All_Email.url
| `drop_dm_object_name(All_Email)`
```

**Defender KQL:**
```kql
let IocDomains = dynamic(["dashboard-bl.pamconj.com","spx.pamconj.com","clear90489058903-document.workers.dev","authdocspro.com","backdoor-hub.com","docusend.networkssolutionmail.com","eventcalender-schedule.com","evobothub.org","framebound.cloud","infinitechai.org","internalmemorecord.bxwancheng.com","mirsanotolastik.com","mirzanyapi.com","newmobilepolojean.com","notificationsmanagersec.com","promanager.outboundciwidey.com","serenitygovsupplys.com","signaturerequired.thecoolcactus.com","statushelper.aguasomos.com","suctwocesonesstory.com"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| join kind=inner (EmailUrlInfo | where Timestamp > ago(30d) | project NetworkMessageId, Url, UrlDomain) on NetworkMessageId
| where UrlDomain in~ (IocDomains) or UrlDomain matches regex @"(?i)-(document|docviewer|onedrive|adobe2)\.workers\.dev$"
| project Timestamp, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, Url, UrlDomain, NetworkMessageId
| order by Timestamp desc
```

### Successful Entra device-code authentication (EvilTokens/ARToken MFA bypass)

`UC_29_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Authentication.app) as app values(Authentication.src) as src min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action=success Authentication.signature="deviceCode" by Authentication.user
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
// AADSignInEventsBeta has no AuthenticationProtocol column, so pivot on the device-code -> PRT app: Microsoft Authentication Broker (clientMode:broker per Talos)
let Baseline = AADSignInEventsBeta
    | where Timestamp between (ago(30d) .. ago(1d))
    | where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e"
    | summarize by AccountUpn, Country;
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e"   // Microsoft Authentication Broker — mints the PRT
| join kind=leftanti Baseline on AccountUpn, Country
| project Timestamp, AccountUpn, Application, IPAddress, Country, City, DeviceName, DeviceTrustType, ClientAppUsed
| order by Timestamp desc
```

### Entra device registration by a user who just completed device-code auth (PRT persistence)

`UC_29_8` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="o365:management:activity" Workload=AzureActiveDirectory (Operation="Add device" OR Operation="Register device" OR Operation="Add registered owner to device")
| stats count min(_time) as firstTime max(_time) as lastTime values(ClientIP) as src by UserId Operation
| sort - firstTime
```

**Defender KQL:**
```kql
// A newly-registered device authenticating = candidate attacker device holding a PRT
let KnownDevices = AADSignInEventsBeta
    | where Timestamp between (ago(30d) .. ago(1d))
    | where isnotempty(AadDeviceId)
    | summarize by AccountUpn, AadDeviceId;
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where DeviceTrustType == "Azure AD registered"
| join kind=leftanti KnownDevices on AccountUpn, AadDeviceId
| project Timestamp, AccountUpn, AadDeviceId, DeviceName, DeviceTrustType, IPAddress, Country, City, Application
| order by Timestamp desc
```

### Malicious inbox rule that hides/deletes/forwards mail (ARToken BEC evidence suppression)

`UC_29_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="o365:management:activity" Workload=Exchange (Operation="New-InboxRule" OR Operation="Set-InboxRule" OR Operation="UpdateInboxRules")
| eval params=mvjoin('Parameters{}.Value', "|")
| where match(params, "(?i)DeleteMessage|MoveToFolder|ForwardTo|RedirectTo|ForwardAsAttachmentTo|MarkAsRead|Deleted Items|Junk|RSS")
| stats count min(_time) as firstTime max(_time) as lastTime values(Operation) as ops by UserId ClientIP
| sort - firstTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Update-InboxRules")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("DeleteMessage", "MoveToFolder", "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "MarkAsRead")
| where Raw has_any ("Deleted Items", "Junk", "RSS", "Archive", "DeleteMessage", "ForwardTo", "RedirectTo")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, ActionType, ObjectName, RawEventData
| order by Timestamp desc
```

### Endpoint egress/DNS to ARToken phishing domains and {uuid}-service.workers.dev hosts

`UC_29_10` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (DNS.query IN ("dashboard-bl.pamconj.com","spx.pamconj.com","clear90489058903-document.workers.dev","authdocspro.com","backdoor-hub.com","docusend.networkssolutionmail.com","eventcalender-schedule.com","evobothub.org","framebound.cloud","infinitechai.org","internalmemorecord.bxwancheng.com","mirsanotolastik.com","mirzanyapi.com","newmobilepolojean.com","notificationsmanagersec.com","promanager.outboundciwidey.com","serenitygovsupplys.com","signaturerequired.thecoolcactus.com","statushelper.aguasomos.com","suctwocesonesstory.com") OR DNS.query="*-document.workers.dev" OR DNS.query="*-docviewer.workers.dev" OR DNS.query="*-onedrive.workers.dev" OR DNS.query="*-adobe2.workers.dev") by DNS.src DNS.query
| `drop_dm_object_name(DNS)`
```

**Defender KQL:**
```kql
let IocDomains = dynamic(["dashboard-bl.pamconj.com","spx.pamconj.com","clear90489058903-document.workers.dev","authdocspro.com","backdoor-hub.com","docusend.networkssolutionmail.com","eventcalender-schedule.com","evobothub.org","framebound.cloud","infinitechai.org","internalmemorecord.bxwancheng.com","mirsanotolastik.com","mirzanyapi.com","newmobilepolojean.com","notificationsmanagersec.com","promanager.outboundciwidey.com","serenitygovsupplys.com","signaturerequired.thecoolcactus.com","statushelper.aguasomos.com","suctwocesonesstory.com"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (IocDomains) or RemoteUrl matches regex @"(?i)-(document|docviewer|onedrive|adobe2)\.workers\.dev"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Bulk SharePoint/OneDrive download fan-out after M365 account takeover (ARToken data theft)

`UC_29_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="o365:management:activity" (Workload=SharePoint OR Workload=OneDrive) Operation="FileDownloaded"
| stats count as downloads dc(ObjectId) as distinctFiles values(Site_Url) as sites min(_time) as firstTime max(_time) as lastTime by UserId ClientIP
| where downloads>100 AND distinctFiles>50
| sort - downloads
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft SharePoint Online", "Microsoft OneDrive for Business")
| where ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Downloads = count(), DistinctFiles = dcount(ObjectId), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), IPs = make_set(IPAddress, 20) by AccountObjectId, AccountDisplayName
| where Downloads > 100 and DistinctFiles > 50   // bulk-staging threshold; tune to org P99
| order by Downloads desc
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
  - IP / domain IOC(s): `dashboard-bl.pamconj.com`, `spx.pamconj.com`, `clear90489058903-document.workers.dev`, `authdocspro.com`, `backdoor-hub.com`, `docusend.networkssolutionmail.com`, `eventcalender-schedule.com`, `evobothub.org` _(+21 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
