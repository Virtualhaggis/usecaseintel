# [CRIT] ConsentFix v3 attacks target Azure with automated OAuth abuse

**Source:** BleepingComputer
**Published:** 2026-05-02
**Article:** https://www.bleepingcomputer.com/news/security/consentfix-v3-attacks-target-azure-with-automated-oauth-abuse/

## Threat Profile

ConsentFix v3 attacks target Azure with automated OAuth abuse 
By Bill Toulas 
May 2, 2026
10:32 AM
0 
A new attack type, dubbed ConsentFix v3, has been circulating on hacker forums as an improved technique that automates attacks against Microsoft Azure.
The first version of ConsentFix was presented by Push Security last December as a variation of ClickFix for OAuth phishing attacks, which tricks victims into completing a legitimate Microsoft login flow via the Azure CLI.
Using social engineerin…

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1566.002** — Phishing: Spearphishing Link
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1567** — Exfiltration Over Web Service
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Browser-mediated interactive sign-in to Azure CLI first-party app (ConsentFix v3)

`UC_13_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.user_agent) as user_agent values(Authentication.signature) as signature from datamodel=Authentication where (Authentication.app="Microsoft Azure CLI" OR Authentication.app="04b07795-8ddb-461a-bbee-02f9e1bf7b46") AND Authentication.action="success" by Authentication.user Authentication.app | `drop_dm_object_name(Authentication)` | search signature="Browser" OR user_agent IN ("*Mozilla*","*Chrome*","*Edg/*","*Safari*","*Firefox*") | where NOT match(user_agent,"(?i)python-requests|azure-cli|msal-python|go-http-client") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// ConsentFix v3 — browser-channel auth-code grant against Azure CLI first-party app
let AzureCliAppId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ApplicationId == AzureCliAppId
| where ErrorCode == 0
| where IsInteractive == true
| where ClientAppUsed =~ "Browser"   // Azure CLI normally = "Mobile Apps and Desktop clients"
| project Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, City,
          Application, ApplicationId, ResourceDisplayName, ClientAppUsed,
          UserAgent, ConditionalAccessStatus, RiskLevelDuringSignIn,
          AuthenticationRequirement, AuthenticationDetails
| order by Timestamp desc
```

### [LLM] Endpoint browser egress to Pipedream webhook after Azure CLI sign-in (ConsentFix v3 token exfil)

`UC_13_6` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Web.url) as urls values(Web.user_agent) as user_agents from datamodel=Web where (Web.url="*m.pipedream.net*" OR Web.url="*pipedream.com*" OR Web.dest="*.m.pipedream.net") AND Web.app IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","safari") by Web.src Web.user Web.dest | `drop_dm_object_name(Web)` | join type=inner user [ | tstats summariesonly=true min(_time) as signinTime from datamodel=Authentication where (Authentication.app="Microsoft Azure CLI" OR Authentication.app="04b07795-8ddb-461a-bbee-02f9e1bf7b46") AND Authentication.action="success" by Authentication.user | `drop_dm_object_name(Authentication)` ] | where firstSeen >= signinTime AND firstSeen <= signinTime + 300 | eval delaySec=firstSeen-signinTime
```

**Defender KQL:**
```kql
// ConsentFix v3 — Pipedream webhook egress paired with Azure CLI sign-in
let AzureCliAppId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
let WindowSec = 300;
let PipedreamHits =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","arc.exe")
    | where RemoteUrl has_any ("m.pipedream.net","pipedream.com")
    | project NetTime = Timestamp, DeviceId, DeviceName,
              InitiatingProcessAccountUpn, InitiatingProcessFileName,
              InitiatingProcessCommandLine, RemoteUrl, RemoteIP;
let AzureCliSignins =
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ApplicationId == AzureCliAppId
    | where ErrorCode == 0 and IsInteractive == true
    | project SigninTime = Timestamp, AccountUpn, IPAddress, ClientAppUsed;
PipedreamHits
| join kind=inner AzureCliSignins on $left.InitiatingProcessAccountUpn == $right.AccountUpn
| where NetTime between (SigninTime .. SigninTime + WindowSec * 1s)
| extend DelaySec = datetime_diff('second', NetTime, SigninTime)
| project SigninTime, NetTime, DelaySec, DeviceName, AccountUpn,
          InitiatingProcessFileName, RemoteUrl, RemoteIP, ClientAppUsed
| order by NetTime desc
```

### [LLM] Inbound phishing email containing DocSend-hosted PDF link (ConsentFix v3 lure)

`UC_13_7` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Email.subject) as subjects values(Email.url) as urls from datamodel=Email where Email.url="*docsend.com*" AND Email.direction="inbound" AND Email.action="delivered" by Email.src_user Email.recipient | `drop_dm_object_name(Email)` | rex field=urls "https?:\/\/(?<docsend_host>[^\/\s\"]*docsend\.com)\/(?<docsend_path>[A-Za-z0-9\/]+)" | `security_content_ctime(firstSeen)` | `security_content_ctime(lastSeen)`
```

**Defender KQL:**
```kql
// ConsentFix v3 — inbound email with DocSend-hosted lure
EmailEvents
| where Timestamp > ago(14d)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| join kind=inner (
    EmailUrlInfo
    | where UrlDomain endswith "docsend.com"
    | project NetworkMessageId, Url, UrlDomain, UrlLocation
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress,
          SenderFromDomain, RecipientEmailAddress, Subject,
          Url, UrlDomain, UrlLocation, DeliveryAction, DeliveryLocation,
          AuthenticationDetails, ThreatTypes
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


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
