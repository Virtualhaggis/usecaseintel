# [HIGH] Researchers report Amazon SES abused in phishing to evade detection

**Source:** BleepingComputer
**Published:** 2026-05-04
**Article:** https://www.bleepingcomputer.com/news/security/researchers-report-amazon-ses-abused-in-phishing-to-evade-detection/

## Threat Profile

Researchers report Amazon SES abused in phishing to evade detection 
By Bill Toulas 
May 4, 2026
04:03 PM
0 
Cybersecurity firm Kaspersky reports that the Amazon Simple Email Service (SES) is being increasingly abused to send convincing phishing emails that can bypass standard security filters and render reputation-based blocks ineffective.
Although the resource has been leveraged for malicious activity in the past, Kaspersky says the current spike may be due to a large number of AWS Identity an…

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
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1586.002** — Compromise Accounts: Email Accounts
- **T1566.002** — Phishing: Spearphishing Link
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1656** — Impersonation
- **T1583.006** — Acquire Infrastructure: Web Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Amazon SES IAM key abuse: quota/identity recon followed by bulk SendEmail from same principal

`UC_42_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count(eval(match('All_Changes.command', "^(GetSendQuota|GetSendStatistics|VerifyEmailIdentity|ListIdentities|GetAccountSendingEnabled|GetIdentityVerificationAttributes)$"))) AS ReconCalls count(eval(match('All_Changes.command', "^(SendEmail|SendRawEmail|SendBulkTemplatedEmail|SendTemplatedEmail)$"))) AS SendCalls values(All_Changes.command) AS ApiCalls min(_time) AS FirstSeen max(_time) AS LastSeen FROM datamodel=Change WHERE All_Changes.vendor_product="Amazon Web Services" All_Changes.object_category="cloud" All_Changes.command IN ("GetSendQuota","GetSendStatistics","VerifyEmailIdentity","ListIdentities","GetAccountSendingEnabled","GetIdentityVerificationAttributes","SendEmail","SendRawEmail","SendBulkTemplatedEmail","SendTemplatedEmail") BY All_Changes.user All_Changes.src All_Changes.user_type | `drop_dm_object_name("All_Changes")` | where ReconCalls>=1 AND SendCalls>=50 AND user_type IN ("IAMUser","AssumedRole") | eval WindowMinutes=round((LastSeen-FirstSeen)/60,1) | where WindowMinutes<=60
```

**Defender KQL:**
```kql
// Defender for Cloud Apps AWS connector — CloudAppEvents carries CloudTrail records under Application 'Amazon Web Services'
let ReconApis = dynamic(["GetSendQuota","GetSendStatistics","VerifyEmailIdentity","ListIdentities","GetAccountSendingEnabled","GetIdentityVerificationAttributes"]);
let SendApis  = dynamic(["SendEmail","SendRawEmail","SendBulkTemplatedEmail","SendTemplatedEmail"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Amazon Web Services"
| where ActionType in (ReconApis) or ActionType in (SendApis)
| extend Raw = parse_json(RawEventData)
| extend EventSource = tostring(Raw.eventSource), UserType = tostring(Raw.userIdentity.type), UserName = tostring(Raw.userIdentity.userName), AccessKeyId = tostring(Raw.userIdentity.accessKeyId)
| where EventSource =~ "ses.amazonaws.com"
| where UserType in ("IAMUser","AssumedRole")
| summarize ReconCalls = countif(ActionType in (ReconApis)),
            SendCalls  = countif(ActionType in (SendApis)),
            ApiCalls   = make_set(ActionType),
            FirstSeen  = min(Timestamp),
            LastSeen   = max(Timestamp)
            by UserName, AccessKeyId, IPAddress, CountryCode
| where ReconCalls >= 1 and SendCalls >= 50
| extend WindowMinutes = datetime_diff('minute', LastSeen, FirstSeen)
| where WindowMinutes <= 60
| order by SendCalls desc
```

### [LLM] Inbound Amazon-SES-authenticated phishing: DocuSign lure with AWS-hosted destination URL

`UC_42_5` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) AS FirstSeen max(_time) AS LastSeen values(All_Email.subject) AS Subjects values(All_Email.url) AS Urls values(All_Email.recipient) AS Recipients FROM datamodel=Email WHERE All_Email.direction="inbound" All_Email.delivery_action IN ("Delivered","DeliveredAsSpam") (All_Email.src_user_domain="*.amazonses.com" OR All_Email.message_id="*amazonses.com*" OR All_Email.return_path="*amazonses.com*") (All_Email.subject="*DocuSign*" OR All_Email.subject="*please review*" OR All_Email.subject="*signature requested*" OR All_Email.subject="*document is ready*" OR All_Email.subject="*sign and return*" OR All_Email.subject="*invoice*" OR All_Email.subject="*payment approval*") (All_Email.url="*.amazonaws.com*" OR All_Email.url="*.cloudfront.net*" OR All_Email.url="*.awsapps.com*") BY All_Email.src_user All_Email.recipient All_Email.message_id | `drop_dm_object_name("All_Email")` | sort -count
```

**Defender KQL:**
```kql
let DocuSignLures = dynamic(["DocuSign","docusign","please review","signature requested","document is ready","sign and return","completed document","invoice attached","payment approval","wire instructions","e-sign"]);
let AwsHostedDomains = dynamic(["amazonaws.com",".cloudfront.net",".awsapps.com",".s3.amazonaws.com",".execute-api.amazonaws.com"]);
let SesMail = EmailEvents
    | where Timestamp > ago(7d)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    | where SenderMailFromDomain endswith ".amazonses.com"
         or SenderFromDomain endswith ".amazonses.com"
         or InternetMessageId has "amazonses.com"
         or AuthenticationDetails has "amazonses.com"
    | where Subject has_any (DocuSignLures);
SesMail
| join kind=inner (
    EmailUrlInfo
    | where Timestamp > ago(7d)
    | project NetworkMessageId, Url, UrlDomain, UrlLocation
  ) on NetworkMessageId
| where UrlDomain has_any (AwsHostedDomains)
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress,
          SenderMailFromDomain, RecipientEmailAddress, Subject,
          Url, UrlDomain, UrlLocation, DeliveryAction, DeliveryLocation,
          AuthenticationDetails
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

Severity classified as **HIGH** based on: 6 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
