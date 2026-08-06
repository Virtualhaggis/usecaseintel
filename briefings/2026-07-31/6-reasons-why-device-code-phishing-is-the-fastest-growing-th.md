# [CRIT] 6 Reasons Why Device Code Phishing is the Fastest-Growing Threat of 2026

**Source:** The Hacker News
**Published:** 2026-07-31
**Article:** https://thehackernews.com/2026/07/6-reasons-why-device-code-phishing-is.html

## Threat Profile

6 Reasons Why Device Code Phishing is the Fastest-Growing Threat of 2026 
 The Hacker News  Jul 31, 2026 Phishing / Browser Security 
Device code phishing - the abuse of the OAuth 2.0 device authorization grant to steal access tokens - has evolved from a niche red-team technique to an industrial-scale threat in under six months.
Designed for input-constrained devices like smart TVs, printers, and so on, the device authorization login flow has been adopted by a wide range of apps and use-cases …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

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
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1098.005** — Account Manipulation: Device Registration
- **T1566.002** — Phishing: Spearphishing Link
- **T1114.002** — Email Collection: Remote Email Collection
- **T1213.002** — Data from Information Repositories: SharePoint

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Entra ID device-code grant to first-time user via Microsoft Authentication Broker

`UC_103_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.signature_id="29d9ed98-a469-4536-ade2-f981bc1d605e" Authentication.action=success by Authentication.user Authentication.src Authentication.app | `drop_dm_object_name(Authentication)` | `security_content_ctime(firstTime)` | eval isFirstSeen=1 | search app="Microsoft Authentication Broker" OR signature_id="29d9ed98-a469-4536-ade2-f981bc1d605e"
```

**Defender KQL:**
```kql
let AuthBroker = "29d9ed98-a469-4536-ade2-f981bc1d605e";  // Microsoft Authentication Broker (Storm-2372 device-code / PRT registration app)
let Baseline = AADSignInEventsBeta
    | where Timestamp between (ago(30d) .. ago(1d))
    | where ErrorCode == 0 and ApplicationId == AuthBroker
    | summarize by AccountUpn;
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0 and ApplicationId == AuthBroker
| where AccountUpn !endswith "$"
| join kind=leftanti Baseline on AccountUpn
| project Timestamp, AccountUpn, AppDisplayName, ResourceDisplayName, IPAddress, Country, City, UserAgent, ClientAppUsed, DeviceTrustType
| order by Timestamp desc
```

### Device-code sign-in from country never seen for the user (stolen-code redemption)

`UC_103_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action=success Authentication.app IN ("Microsoft Authentication Broker","Microsoft Azure CLI","Microsoft Azure PowerShell","Microsoft Office","Visual Studio Code") by Authentication.user Authentication.src Authentication.app _time span=1h | `drop_dm_object_name(Authentication)` | iplocation src | eventstats values(Country) as historicCountries by user | eval newCountry=if(isnull(mvfind(historicCountries,Country)),1,0) | where newCountry=1
```

**Defender KQL:**
```kql
let DeviceCodeApps = dynamic(["29d9ed98-a469-4536-ade2-f981bc1d605e","04b07795-8ddb-461a-bbee-02f9e1bf7b46","1950a258-227b-4e31-a9cf-717495945fc2","d3590ed6-52b3-4102-aeff-aad2292ab01c","aebc6443-996d-45c2-90f0-388ff96faa56"]);  // device-code-capable first-party clients
let Baseline = AADSignInEventsBeta
    | where Timestamp between (ago(30d) .. ago(1d))
    | where ErrorCode == 0 and isnotempty(Country)
    | summarize by AccountUpn, Country;
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where ApplicationId in (DeviceCodeApps)
| where isnotempty(Country) and AccountUpn !endswith "$"
| join kind=leftanti Baseline on AccountUpn, Country
| project Timestamp, AccountUpn, AppDisplayName, ApplicationId, ResourceDisplayName, IPAddress, Country, City, UserAgent, IsAnonymousProxy
| order by Timestamp desc
```

### Stolen device-code token fanning out to multiple SSO resources within the hour

`UC_103_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Authentication.dest) as distinctResources values(Authentication.dest) as resources values(Authentication.src) as srcIPs min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action=success Authentication.app IN ("Microsoft Authentication Broker","Microsoft Azure CLI","Microsoft Azure PowerShell","Microsoft Office","Visual Studio Code") by Authentication.user _time span=1h | `drop_dm_object_name(Authentication)` | where distinctResources>=5
```

**Defender KQL:**
```kql
let DeviceCodeApps = dynamic(["29d9ed98-a469-4536-ade2-f981bc1d605e","04b07795-8ddb-461a-bbee-02f9e1bf7b46","1950a258-227b-4e31-a9cf-717495945fc2","d3590ed6-52b3-4102-aeff-aad2292ab01c","aebc6443-996d-45c2-90f0-388ff96faa56"]);
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0 and IsInteractive == false
| where ApplicationId in (DeviceCodeApps)
| where AccountUpn !endswith "$"
| summarize DistinctResources = dcount(ResourceDisplayName), Resources = make_set(ResourceDisplayName, 25), IPs = make_set(IPAddress, 10), StartTime = min(Timestamp), EndTime = max(Timestamp) by AccountUpn, bin(Timestamp, 1h)
| where DistinctResources >= 5   // 1 device-code token hitting >=5 distinct SSO resources in 1h (legit CLI/PS use ~1-3)
| order by DistinctResources desc
```

### New Entra device registration shortly after a device-code grant (PRT persistence)

`UC_103_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Change where Change.action=created Change.object_category="device" (Change.command="Add device" OR Change.command="Register device" OR Change.command="Add registered owner to device") by Change.user Change.src _time | `drop_dm_object_name(Change)`
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 0
| where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e"   // Microsoft Authentication Broker
| where ResourceDisplayName has "Device Registration"
| where AccountUpn !endswith "$"
| project Timestamp, AccountUpn, AppDisplayName, ResourceDisplayName, IPAddress, Country, City, UserAgent, DeviceName, AadDeviceId, DeviceTrustType
| order by Timestamp desc
```

### Phishing email delivering a Microsoft/GitHub device-login URL

`UC_103_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Email where Email.direction=inbound (Email.url="*devicelogin*" OR Email.url="*oauth2/deviceauth*" OR Email.url="*login/device*" OR Email.url="*aka.ms/devicelogin*") by Email.src_user Email.recipient Email.subject Email.url _time | `drop_dm_object_name(Email)` | sort - _time
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| join kind=inner (
    EmailUrlInfo
    | where Timestamp > ago(7d)
    | where Url has_any ("devicelogin","oauth2/deviceauth","login/device","aka.ms/devicelogin","amazon.com/verification")
    | project NetworkMessageId, Url, UrlDomain
  ) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryLocation, PhishConfidenceLevel
| order by Timestamp desc
```

### Bulk mailbox and SharePoint collection from a device-code-authorized session

`UC_103_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as ops sum(eval(if(Operation=="MailItemsAccessed",1,0))) as mailAccessed sum(eval(if(Operation IN ("FileDownloaded","FileSyncDownloadedFull"),1,0))) as downloads from datamodel=Email where Email.Operation IN ("MailItemsAccessed","FileDownloaded","FileSyncDownloadedFull","SearchQueryPerformed") by Email.user Email.src _time span=1h | `drop_dm_object_name(Email)` | where ops>=50
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(1d)
| where ActionType in ("MailItemsAccessed","FileDownloaded","FileSyncDownloadedFull","SearchQueryPerformed")
| summarize Ops = count(), MailAccessed = countif(ActionType == "MailItemsAccessed"), Downloads = countif(ActionType in ("FileDownloaded","FileSyncDownloadedFull")), Searches = countif(ActionType == "SearchQueryPerformed") by AccountObjectId, AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where Ops >= 50   // bulk mailbox/SharePoint burst; correlate account with a recent device-code sign-in (AADSignInEventsBeta AppId 29d9ed98-...)
| order by Ops desc
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


## Why this matters

Severity classified as **CRIT** based on: 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
