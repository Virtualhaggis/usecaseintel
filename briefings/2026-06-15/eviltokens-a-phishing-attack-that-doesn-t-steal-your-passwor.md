# [HIGH] EvilTokens: A phishing attack that doesn’t steal your password

**Source:** ESET WeLiveSecurity
**Published:** 2026-06-15
**Article:** https://www.welivesecurity.com/en/cybercrime/eviltokens-phishing-doesnt-steal-password/

## Threat Profile

Much has been written about how the days of phishing emails laden with broken grammar and crude design are numbered, largely thanks to AI. Meanwhile, EvilTokens offers a somewhat different example of how far the phishing craft has moved.
EvilTokens is a phishing-as-a-service (PhaaS) kit built to compromise Microsoft 365 accounts by abusing the OAuth 2.0 device authorization grant flow . As attacks that use the kit rely on device code phishing, they sidestep the need for convincing replicas of ge…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `162.220.232.0`
- **IPv4 (defanged):** `162.220.234.0`
- **IPv4 (defanged):** `89.150.45.0`
- **IPv4 (defanged):** `185.81.113.0`
- **Domain (defanged):** `authdocspro.com`
- **Domain (defanged):** `backdoor-hub.com`
- **Domain (defanged):** `bumpgames.net`
- **Domain (defanged):** `carbatterygurgaon.com`
- **Domain (defanged):** `careldutoit-el.co.za`
- **Domain (defanged):** `dao.com.au`
- **Domain (defanged):** `docusend.networkssolutionmail.com`
- **Domain (defanged):** `eqfit.co.za`
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
- **Domain (defanged):** `thesafarigarden.com`
- **Domain (defanged):** `topbuysella.com`
- **Domain (defanged):** `totalhomesafe.com`
- **Domain (defanged):** `youremplregroup.com`

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
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1566** — Phishing
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1114.003** — Email Collection: Email Forwarding Rule

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### EvilTokens lure email - inbound message referencing microsoft.com/devicelogin or device code prompts

`UC_126_6` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where Email.direction=inbound (Email.subject="*verify to view*" OR Email.subject="*signature required*" OR Email.subject="*device code*" OR Email.url="*microsoft.com/devicelogin*" OR Email.url="*authdocspro.com*" OR Email.url="*notificationsmanagersec.com*" OR Email.url="*eventcalender-schedule.com*" OR Email.url="*evobothub.org*" OR Email.url="*framebound.cloud*" OR Email.url="*infinitechai.org*" OR Email.url="*backdoor-hub.com*" OR Email.url="*docusend.networkssolutionmail.com*") by Email.src_user Email.recipient Email.subject Email.url | `drop_dm_object_name(Email)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound" and DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject has_any ("verify to view","signature required","device code","devicelogin","shared document","signature requested")
| join kind=inner (
    EmailUrlInfo
    | where Timestamp > ago(7d)
    | where Url has_any ("microsoft.com/devicelogin","oauth2/deviceauth","authdocspro.com","backdoor-hub.com","docusend.networkssolutionmail.com","eventcalender-schedule.com","evobothub.org","framebound.cloud","infinitechai.org","notificationsmanagersec.com","internalmemorecord.bxwancheng.com","newmobilepolojean.com")
) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryAction, AuthenticationDetails
| order by Timestamp desc
```

### Successful Entra ID device code OAuth flow sign-in - EvilTokens authorisation handoff

`UC_126_7` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action=success Authentication.signature="deviceCode" by Authentication.user Authentication.src Authentication.app Authentication.user_agent | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| extend AuthDetailsStr = tostring(AuthenticationDetails)
| extend AuthProcessingStr = tostring(AuthenticationProcessingDetails)
| where AuthDetailsStr has "deviceCode" or AuthProcessingStr has "deviceCode" or AuthenticationRequirement has "deviceCode"
| project Timestamp, AccountUpn, AccountDisplayName, IPAddress, Country, City, Application, AppDisplayName, ApplicationId, UserAgent, DeviceName, AadDeviceId, IsAnonymousProxy, RiskLevelDuringSignIn, RiskState, ConditionalAccessStatus, AuthDetailsStr
| order by Timestamp desc
```

### Host or user contacting EvilTokens C2 / lure infrastructure (IOC sweep)

`UC_126_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (Network_Traffic.All_Traffic.dest in ("162.220.232.0","162.220.234.0","89.150.45.0","185.81.113.0") OR Network_Traffic.All_Traffic.dest_host IN ("authdocspro.com","backdoor-hub.com","bumpgames.net","carbatterygurgaon.com","careldutoit-el.co.za","dao.com.au","docusend.networkssolutionmail.com","eqfit.co.za","eventcalender-schedule.com","evobothub.org","framebound.cloud","infinitechai.org","internalmemorecord.bxwancheng.com","macmamo.com","mirsanotolastik.com","mirzanyapi.com","newmobilepolojean.com","notificationsmanagersec.com","pelangiservice.com","prcservis.com")) by Network_Traffic.All_Traffic.src Network_Traffic.All_Traffic.dest Network_Traffic.All_Traffic.dest_host Network_Traffic.All_Traffic.user | `drop_dm_object_name("Network_Traffic.All_Traffic")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let EvilTokensDomains = dynamic(["authdocspro.com","backdoor-hub.com","bumpgames.net","carbatterygurgaon.com","careldutoit-el.co.za","dao.com.au","docusend.networkssolutionmail.com","eqfit.co.za","eventcalender-schedule.com","evobothub.org","framebound.cloud","infinitechai.org","internalmemorecord.bxwancheng.com","macmamo.com","mirsanotolastik.com","mirzanyapi.com","newmobilepolojean.com","notificationsmanagersec.com","pelangiservice.com","prcservis.com"]);
let EvilTokensIPs = dynamic(["162.220.232.0","162.220.234.0","89.150.45.0","185.81.113.0"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (EvilTokensIPs) 
   or RemoteUrl has_any (EvilTokensDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Protocol
| order by Timestamp desc
```

### Inbox rule creation immediately following Entra ID device code sign-in

`UC_126_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as deviceCodeTime from datamodel=Authentication where Authentication.action=success Authentication.signature="deviceCode" by Authentication.user | `drop_dm_object_name(Authentication)` | join type=inner user [ | tstats `summariesonly` min(_time) as ruleTime from datamodel=Change where Change.action=created Change.object_category="InboxRule" by Change.user | `drop_dm_object_name(Change)` | rename Change.user as user ] | eval diff_sec=ruleTime-deviceCodeTime | where diff_sec>=0 AND diff_sec<=3600 | convert ctime(deviceCodeTime) ctime(ruleTime)
```

**Defender KQL:**
```kql
let DeviceCodeSignIns = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | extend AuthDetailsStr = tostring(AuthenticationDetails)
    | where AuthDetailsStr has "deviceCode" or AuthenticationRequirement has "deviceCode"
    | project DeviceCodeTime = Timestamp, AccountUpn, IPAddress, Application;
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| extend RuleDetails = tostring(RawEventData)
| where RuleDetails has_any ("DeleteMessage","MoveToFolder","ForwardTo","RedirectTo","MarkAsRead")
   or RuleDetails has_any ("RSS Feeds","Archive","Conversation History",".. ","!")
| join kind=inner DeviceCodeSignIns on $left.AccountDisplayName == $right.AccountUpn
| where Timestamp between (DeviceCodeTime .. DeviceCodeTime + 60m)
| extend DelayMinutes = datetime_diff('minute', Timestamp, DeviceCodeTime)
| project DeviceCodeTime, RuleCreatedTime = Timestamp, DelayMinutes, AccountDisplayName, IPAddress, Application, ActionType, ObjectName, RuleDetails
| order by RuleCreatedTime desc
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
  - IP / domain IOC(s): `162.220.232.0`, `162.220.234.0`, `89.150.45.0`, `185.81.113.0`, `authdocspro.com`, `backdoor-hub.com`, `bumpgames.net`, `carbatterygurgaon.com` _(+26 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
