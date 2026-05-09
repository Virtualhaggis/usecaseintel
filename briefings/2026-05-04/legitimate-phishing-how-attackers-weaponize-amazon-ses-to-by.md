# [HIGH] “Legitimate” phishing: how attackers weaponize Amazon SES to bypass email security

**Source:** Securelist (Kaspersky)
**Published:** 2026-05-04
**Article:** https://securelist.com/amazon-ses-phishing-and-bec-attacks/119623/

## Threat Profile

Table of Contents
Introduction 
The dangers of Amazon SES abuse 
How compromise happens 
Examples of phishing with Amazon SES 
Amazon SES and BEC 
Takeaways 
Authors
Roman Dedenok 
Introduction 
The primary goal for attackers in a phishing campaign is to bypass email security and trick the potential victim into revealing their data. To achieve this, scammers employ a wide range of tactics, from redirect links to QR codes. Additionally, they heavily rely on legitimate sources for malicious email …

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1566.002** — Phishing: Spearphishing Link
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1583.006** — Acquire Infrastructure: Web Services
- **T1656** — Impersonation
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1585.002** — Establish Accounts: Email Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound phishing via Amazon SES with e-signature lure linking to AWS-hosted infrastructure

`UC_85_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.subject) as subject values(All_Email.src_user) as sender values(All_Email.message_id) as message_id values(All_Email.url) as url from datamodel=Email where All_Email.direction="inbound" (All_Email.message_id="*amazonses.com*" OR All_Email.src_user="*@*amazonses.com") (All_Email.subject IN ("*docusign*","*adobe sign*","*echosign*","*pandadoc*","*hellosign*","*sign and return*","*please review and sign*","*document for signature*","*signed document*","*completed: please sign*")) (All_Email.url="*amazonaws.com*" OR All_Email.url="*awstrack.me*" OR All_Email.url="*cloudfront.net*") by All_Email.recipient All_Email.src All_Email.message_id | `drop_dm_object_name("All_Email")` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let SignatureLures = dynamic(["docusign","adobe sign","echosign","hellosign","pandadoc","signnow","document for signature","please review and sign","review and sign","signed document","completed: please sign","completed via docusign","action required: sign"]);
let AwsHosted = dynamic(["amazonaws.com","awstrack.me","cloudfront.net","awsapps.com"]);
let SuspectMail = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    // Securelist: SES-routed phishing "almost always contains .amazonses.com in the Message-ID headers"
    | where InternetMessageId has "amazonses.com"
        or SenderMailFromDomain endswith "amazonses.com"
    | where tolower(Subject) has_any (SignatureLures);
SuspectMail
| join kind=inner (
    EmailUrlInfo
    | where Timestamp > ago(LookbackDays)
    | where UrlDomain has_any (AwsHosted)
    | project NetworkMessageId, Url, UrlDomain, UrlLocation
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, InternetMessageId,
          SenderFromAddress, SenderMailFromAddress, SenderMailFromDomain,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          Url, UrlDomain, UrlLocation
| order by Timestamp desc
```

### [LLM] Click on Amazon SES-routed phishing link to AWS-hosted credential-harvest page

`UC_85_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as clickTime values(Web.user) as user values(Web.url) as url values(Web.src) as src values(All_Email.message_id) as message_id values(All_Email.subject) as subject from datamodel=Web where Web.url IN ("*amazonaws.com*","*awstrack.me*","*cloudfront.net*") by Web.user Web.dest Web.url | join type=inner user [| tstats `summariesonly` count from datamodel=Email where All_Email.direction="inbound" All_Email.message_id="*amazonses.com*" by All_Email.recipient All_Email.message_id All_Email.subject | rename All_Email.recipient as user] | `security_content_ctime(clickTime)`
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let AwsHosted = dynamic(["amazonaws.com","awstrack.me","cloudfront.net","awsapps.com"]);
let SesEmails = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    | where InternetMessageId has "amazonses.com"
        or SenderMailFromDomain endswith "amazonses.com"
    | project NetworkMessageId, EmailTime = Timestamp,
              SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
              Subject, InternetMessageId;
let SesUrls = SesEmails
    | join kind=inner (
        EmailUrlInfo
        | where Timestamp > ago(LookbackDays)
        | where UrlDomain has_any (AwsHosted)
        | project NetworkMessageId, Url, UrlDomain
      ) on NetworkMessageId;
UrlClickEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("ClickAllowed","ClickedThrough")
| where Url has_any (AwsHosted)
| join kind=inner SesUrls on $left.Url == $right.Url
| project ClickTime = Timestamp, AccountUpn, IPAddress, ActionType,
          IsClickedThrough, EmailTime, SenderFromAddress, RecipientEmailAddress,
          Subject, InternetMessageId, Url, UrlDomain
| order by ClickTime desc
```

### [LLM] Compromised IAM key prepares SES for mass phishing (CreateAccessKey + AttachUserPolicy + SendEmail burst)

`UC_85_6` · phase: **weapon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`cloudtrail` eventSource IN ("ses.amazonaws.com","email.amazonaws.com","iam.amazonaws.com","support.amazonaws.com") eventName IN ("SendEmail","SendRawEmail","SendBulkTemplatedEmail","VerifyEmailIdentity","VerifyDomainIdentity","UpdateAccountSendingEnabled","PutAccountDetails","CreateAccessKey","AttachUserPolicy","CreatePolicy","CreateCase") | stats count earliest(_time) as firstTime latest(_time) as lastTime values(eventName) as eventNames values(awsRegion) as regions dc(eventName) as uniqueEventNames by userIdentity.userName userIdentity.accountId sourceIPAddress | where uniqueEventNames>=2 AND mvfind(eventNames,"SendEmail|SendRawEmail|SendBulkTemplatedEmail|UpdateAccountSendingEnabled")>=0 AND mvfind(eventNames,"CreateAccessKey|AttachUserPolicy|CreatePolicy|CreateCase")>=0 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LookbackHours = 24h;
let SesActions = dynamic(["SendEmail","SendRawEmail","SendBulkTemplatedEmail","VerifyEmailIdentity","VerifyDomainIdentity","UpdateAccountSendingEnabled","PutAccountDetails","CreateConfigurationSet","CreateEmailIdentity"]);
let StagingActions = dynamic(["CreateAccessKey","AttachUserPolicy","CreatePolicy","CreateCase","PutUserPolicy"]);
CloudAppEvents
| where Timestamp > ago(LookbackHours)
| where Application has_any ("Amazon Web Services","AWS")
| extend Raw = parse_json(tostring(RawEventData))
| extend EventName = tostring(Raw.eventName),
         EventSource = tostring(Raw.eventSource),
         AwsRegion = tostring(Raw.awsRegion),
         PolicyName = tostring(Raw.requestParameters.policyName),
         AccessKeyId = tostring(Raw.userIdentity.accessKeyId),
         PrincipalArn = tostring(Raw.userIdentity.arn)
| where EventName in (SesActions) or EventName in (StagingActions)
| summarize Events = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SesEventsSeen = make_set_if(EventName, EventName in (SesActions)),
            StagingEventsSeen = make_set_if(EventName, EventName in (StagingActions)),
            SuspiciousPolicies = make_set_if(PolicyName, PolicyName has_any ("ses","support","admin","FullAccess")),
            Regions = make_set(AwsRegion, 10),
            SourceIPs = make_set(IPAddress, 10),
            Countries = make_set(CountryCode, 10)
            by PrincipalArn, AccessKeyId
| where array_length(SesEventsSeen) > 0 and array_length(StagingEventsSeen) > 0
| order by Events desc
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

Severity classified as **HIGH** based on: 7 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
