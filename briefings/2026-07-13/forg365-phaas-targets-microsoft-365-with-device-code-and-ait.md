# [CRIT] Forg365 PhaaS Targets Microsoft 365 with Device Code and AitM Session Theft

**Source:** The Hacker News
**Published:** 2026-07-13
**Article:** https://thehackernews.com/2026/07/forg365-phaas-targets-microsoft-365.html

## Threat Profile

Forg365 PhaaS Targets Microsoft 365 with Device Code and AitM Session Theft 
 Ravie Lakshmanan  Jul 13, 2026 Email Security / Artificial Intelligence 
A new phishing-as-a-service (PhaaS) operation called Forg365 is using a combination of device code phishing , adversary-in-the-middle (AitM) tactics, antibot evasion, artificial intelligence (AI)-assisted lure creation, and post-compromise mailbox operations targeting Microsoft 365 accounts.
Distributed via Telegram and costing $400 a month (or …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `logfriend.com`
- **Domain (defanged):** `login.microsoftonline.com`

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
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1621** — Multi-Factor Authentication Request Generation
- **T1566.002** — Phishing: Spearphishing Link
- **T1598.003** — Phishing for Information: Spearphishing Link
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1098.003** — Account Manipulation: Additional Cloud Roles

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### First-seen Entra device-code auth via Microsoft Authentication Broker (Forg365)

`UC_106_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.signature) as signature from datamodel=Authentication where Authentication.app="Microsoft Authentication Broker" Authentication.action=success by Authentication.user | `drop_dm_object_name(Authentication)` | eval firstTime_h=strftime(firstTime,"%F %T") | sort - firstTime
```

**Defender KQL:**
```kql
let Broker = "29d9ed98-a469-4536-ade2-f981bc1d605e"; let Lookback = 14d; let Baseline = AADSignInEventsBeta | where Timestamp between (ago(45d) .. ago(Lookback)) | where ApplicationId == Broker and ErrorCode == 0 | distinct AccountUpn; AADSignInEventsBeta | where Timestamp > ago(Lookback) | where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e"  // Microsoft Authentication Broker | where ErrorCode == 0 | where ResourceDisplayName !in ("Device Registration Service","Microsoft Device Registration Client") | where AccountUpn !in (Baseline)   // first broker device-code success for this user in 45d | summarize FirstSeen=min(Timestamp), Sessions=count(), Resources=make_set(ResourceDisplayName), IPs=make_set(IPAddress), Countries=make_set(Country), UserAgents=make_set(UserAgent) by AccountUpn | order by FirstSeen desc
```

### Broker device-code sign-in from Node.js automation UA (Forg365 operator backend)

`UC_106_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src from datamodel=Authentication where Authentication.app="Microsoft Authentication Broker" Authentication.action=success (Authentication.user_agent="*node*" OR Authentication.user_agent="*undici*" OR Authentication.user_agent="*axios*" OR Authentication.user_agent="*python-requests*") by Authentication.user Authentication.user_agent | `drop_dm_object_name(Authentication)` | sort - firstTime
```

**Defender KQL:**
```kql
AADSignInEventsBeta | where Timestamp > ago(14d) | where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e"  // Microsoft Authentication Broker | where ErrorCode == 0 | where UserAgent has_any ("node","undici","axios","python-requests","Go-http-client","okhttp") | project Timestamp, AccountUpn, IPAddress, Country, UserAgent, ResourceDisplayName, IsInteractive | order by Timestamp desc
```

### Forg365 phishing email: Amazon SES sender with SendGrid/logfriend redirect link

`UC_106_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Email.subject) as subject values(Email.recipient) as recipient from datamodel=Email where Email.direction=inbound (Email.src_user="*amazonses.com" OR Email.src="*amazonses.com*") by Email.src_user Email.message_id | `drop_dm_object_name(Email)` | sort - firstTime
```

**Defender KQL:**
```kql
let SesMail = EmailEvents | where Timestamp > ago(14d) | where EmailDirection == "Inbound" and DeliveryAction in ("Delivered","DeliveredAsSpam") | where SenderMailFromDomain endswith "amazonses.com" or SenderFromDomain endswith "amazonses.com"; SesMail | join kind=inner (EmailUrlInfo | project NetworkMessageId, Url, UrlDomain) on NetworkMessageId | where UrlDomain has_any ("sendgrid.net","logfriend.com") or Url has_any ("logfriend.com","sendgrid") | project Timestamp, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, Url, UrlDomain, NetworkMessageId | order by Timestamp desc
```

### M365 broker token replay from anomalous country after interactive login (AitM/ForgCookie)

`UC_106_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.app="Microsoft Authentication Broker" Authentication.action=success by Authentication.user Authentication.src _time span=1h | `drop_dm_object_name(Authentication)` | iplocation src | stats dc(Country) as countries values(Country) as countries_list values(src) as srcs by user | where countries>1
```

**Defender KQL:**
```kql
let Broker = "29d9ed98-a469-4536-ade2-f981bc1d605e"; let Window = 12h; let Interactive = AADSignInEventsBeta | where Timestamp > ago(7d) | where ErrorCode == 0 and IsInteractive == true and isnotempty(Country) | project IntTime=Timestamp, AccountUpn, IntCountry=Country, IntIP=IPAddress; AADSignInEventsBeta | where Timestamp > ago(7d) | where ApplicationId == Broker and ErrorCode == 0 and IsInteractive == false and isnotempty(Country) | project TokTime=Timestamp, AccountUpn, TokCountry=Country, TokIP=IPAddress, UserAgent, ResourceDisplayName | join kind=inner Interactive on AccountUpn | where TokTime between (IntTime .. IntTime + Window) | where TokCountry != IntCountry | project AccountUpn, IntTime, IntCountry, IntIP, TokTime, TokCountry, TokIP, UserAgent, ResourceDisplayName | order by TokTime desc
```

### OAuth consent grant to app with mailbox permissions post-device-code (Forg365 persistence)

`UC_106_12` · phase: **install** · confidence: **Low** · AI-generated for this article

**Defender KQL:**
```kql
CloudAppEvents | where Timestamp > ago(14d) | where ActionType in ("Consent to application","Add OAuth2PermissionGrant","Add delegated permission grant") | where RawEventData has_any ("Mail.Read","Mail.ReadWrite","Mail.Send","MailboxSettings.ReadWrite","offline_access","User.Read.All") | project Timestamp, AccountDisplayName, AccountId, IPAddress, ActionType, ObjectName, ApplicationId, RawEventData | order by Timestamp desc
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
  - IP / domain IOC(s): `logfriend.com`, `login.microsoftonline.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
