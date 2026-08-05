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
- **T1621** — Multi-Factor Authentication Request Generation
- **T1098.005** — Account Manipulation: Device Registration
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1598.003** — Phishing for Information: Spearphishing Link
- **T1566.002** — Phishing: Spearphishing Link
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Successful OAuth 2.0 device code grant from country never seen for the user

`UC_101_6` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action=success Authentication.signature="deviceCode" by Authentication.user Authentication.src Authentication.app Authentication.src_geo_country
| `drop_dm_object_name(Authentication)`
| eventstats dc(src_geo_country) as country_count by user
| where country_count>1
| sort - lastTime
```

**Defender KQL:**
```kql
let Lookback = 30d;
let Recent = 1d;
let KnownCountries = AADSignInEventsBeta
    | where Timestamp between (ago(Lookback) .. ago(Recent))
    | where ErrorCode == 0 and isnotempty(Country)
    | summarize by AccountUpn, Country;
AADSignInEventsBeta
| where Timestamp > ago(Recent)
| where AuthenticationProcessingDetails has "deviceCode"   // AADSignInEventsBeta has no AuthenticationProtocol column
| where ErrorCode == 0 and isnotempty(Country)
| join kind=leftanti KnownCountries on AccountUpn, Country
| project Timestamp, AccountUpn, Country, City, IPAddress, Application, ApplicationId, ResourceDisplayName, UserAgent
| order by Timestamp desc
```

### Device registration / PRT theft via Microsoft Authentication Broker after device code sign-in

`UC_101_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype="o365:management:activity" Workload=AzureActiveDirectory (Operation="Add device" OR Operation="Register device" OR Operation="Add registered owner to device")
| stats count min(_time) as firstTime max(_time) as lastTime values(ClientIP) as src by UserId Operation
| sort - firstTime
```

**Defender KQL:**
```kql
// Device-code sign-in to Microsoft Authentication Broker followed by a first-seen device for the user
let Broker = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ApplicationId == "29d9ed98-a469-4536-ade2-f981bc1d605e"   // Microsoft Authentication Broker (mints PRT)
    | where AuthenticationProcessingDetails has "deviceCode"
    | where ErrorCode == 0
    | project BrokerTime = Timestamp, AccountUpn, IPAddress, Country;
let KnownDevices = AADSignInEventsBeta
    | where Timestamp between (ago(30d) .. ago(7d))
    | where isnotempty(AadDeviceId)
    | summarize by AccountUpn, AadDeviceId;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0 and isnotempty(AadDeviceId)
| join kind=inner Broker on AccountUpn
| where Timestamp between (BrokerTime .. BrokerTime + 2h)
| join kind=leftanti KnownDevices on AccountUpn, AadDeviceId
| project Timestamp, AccountUpn, AadDeviceId, DeviceName, DeviceTrustType, IPAddress, Country, City, Application
| order by Timestamp desc
```

### Anomalous device code authentication request pattern from risky/anonymized source

`UC_101_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action=success Authentication.signature="deviceCode" by Authentication.user Authentication.src Authentication.app _time span=1h
| `drop_dm_object_name(Authentication)`
| stats dc(app) as distinct_apps values(app) as apps values(src) as src by user
| where distinct_apps>=2
| sort - distinct_apps
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AuthenticationProcessingDetails has "deviceCode"
| where ErrorCode == 0
| where IsAnonymousProxy == true or RiskLevelDuringSignIn in ("high", "medium")
| project Timestamp, AccountUpn, IPAddress, Country, City, Application, ResourceDisplayName, RiskLevelDuringSignIn, RiskState, UserAgent
| order by Timestamp desc
```

### Phishing email delivering a device-code login portal link (devicelogin / oauth2 deviceauth)

`UC_101_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email.All_Email where All_Email.direction="inbound" (All_Email.url="*microsoft.com/devicelogin*" OR All_Email.url="*oauth2/deviceauth*" OR All_Email.url="*github.com/login/device*" OR All_Email.url="*aka.ms/devicelogin*" OR All_Email.url="*device.sso.*") by All_Email.src_user All_Email.recipient All_Email.subject All_Email.url
| `drop_dm_object_name(All_Email)`
```

**Defender KQL:**
```kql
let Window = 10m;
let DeviceCodeUrls = dynamic(["microsoft.com/devicelogin", "oauth2/deviceauth", "github.com/login/device", "aka.ms/devicelogin", "device.sso", "login.microsoftonline.com/common/oauth2/deviceauth"]);
let PhishMail = EmailEvents
    | where Timestamp > ago(14d)
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
    | join kind=inner (EmailUrlInfo | where Timestamp > ago(14d) | project NetworkMessageId, Url) on NetworkMessageId
    | where Url has_any (DeviceCodeUrls)
    | project MailTime = Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, Url;
PhishMail
| join kind=inner (
    UrlClickEvents
    | where Timestamp > ago(14d)
    | where ActionType in ("ClickAllowed", "ClickedThrough")
    | project ClickTime = Timestamp, NetworkMessageId, AccountUpn, IPAddress
  ) on NetworkMessageId
| where ClickTime between (MailTime .. MailTime + Window)
| project MailTime, ClickTime, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, AccountUpn, Subject, Url, IPAddress
| order by ClickTime desc
```

### Cloud lateral movement via a compromised device-code token (multi-service fan-out)

`UC_101_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action=success by Authentication.user Authentication.app Authentication.src _time span=6h
| `drop_dm_object_name(Authentication)`
| stats dc(app) as distinct_services values(app) as services by user src
| where distinct_services>=4
| sort - distinct_services
```

**Defender KQL:**
```kql
let DeviceCode = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where AuthenticationProcessingDetails has "deviceCode" and ErrorCode == 0
    | project DcTime = Timestamp, AccountUpn, DcIP = IPAddress;
CloudAppEvents
| where Timestamp > ago(7d)
| join kind=inner DeviceCode on $left.IPAddress == $right.DcIP
| where Timestamp between (DcTime .. DcTime + 6h)
| summarize Apps = dcount(Application), Actions = count(), SampleActions = make_set(ActionType, 15), Services = make_set(Application, 20) by AccountUpn, DcIP, DcTime
| where Apps >= 3   // token driving activity across 3+ distinct cloud apps from the redemption IP
| order by DcTime desc
```

### Device-code flow requested for an unexpected public client application

`UC_101_11` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action=success Authentication.signature="deviceCode" (Authentication.app_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46" OR Authentication.app_id="1950a258-227b-4e31-a9cf-717495945fc2" OR Authentication.app_id="d3590ed6-52b3-4102-aeff-aad2292ab01c" OR Authentication.app_id="29d9ed98-a469-4536-ade2-f981bc1d605e" OR Authentication.app_id="aebc6443-996d-45c2-90f0-388ff96faa56") by Authentication.user Authentication.src Authentication.app_id
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AuthenticationProcessingDetails has "deviceCode"
| where ErrorCode == 0
| where ApplicationId in (
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",   // Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",   // Microsoft Azure PowerShell
    "d3590ed6-52b3-4102-aeff-aad2292ab01c",   // Microsoft Office
    "29d9ed98-a469-4536-ade2-f981bc1d605e",   // Microsoft Authentication Broker
    "aebc6443-996d-45c2-90f0-388ff96faa56")   // Visual Studio Code
| project Timestamp, AccountUpn, Application, ApplicationId, ResourceDisplayName, IPAddress, Country, City, UserAgent
| order by Timestamp desc
```

### Geographic impossibility between device-code entry and token redemption

`UC_101_12` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.action=success by Authentication.user Authentication.signature Authentication.src_geo_country _time span=30m
| `drop_dm_object_name(Authentication)`
| eval flow=if(signature="deviceCode","devicecode","interactive")
| stats values(eval(if(flow="devicecode",src_geo_country,null()))) as dc_country values(eval(if(flow="interactive",src_geo_country,null()))) as user_country by user _time
| where isnotnull(dc_country) AND isnotnull(user_country) AND dc_country!=user_country
| sort - _time
```

**Defender KQL:**
```kql
let Window = 30m;
let Interactive = AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0 and IsInteractive == true
    | where not(AuthenticationProcessingDetails has "deviceCode")
    | project IntTime = Timestamp, AccountUpn, UserCountry = Country, UserIP = IPAddress;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AuthenticationProcessingDetails has "deviceCode" and ErrorCode == 0
| join kind=inner Interactive on AccountUpn
| where IntTime between (Timestamp - Window .. Timestamp + Window)
| where isnotempty(Country) and isnotempty(UserCountry) and Country != UserCountry
| project Timestamp, AccountUpn, DeviceCodeCountry = Country, DeviceCodeIP = IPAddress, UserCountry, UserIP, IntTime
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


## Why this matters

Severity classified as **CRIT** based on: 13 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
