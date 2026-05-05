# [HIGH] Amazon SES increasingly abused in phishing to evade detection

**Source:** BleepingComputer
**Published:** 2026-05-04
**Article:** https://www.bleepingcomputer.com/news/security/amazon-ses-increasingly-abused-in-phishing-to-evade-detection/

## Threat Profile

Amazon SES increasingly abused in phishing to evade detection 
By Bill Toulas 
May 4, 2026
04:03 PM
0 
The Amazon Simple Email Service (SES) is being increasingly abused to send convincing phishing emails that can bypass standard security filters and render reputation-based blocks ineffective.
Although the resource has been leveraged for malicious activity in the past, the current spike may be due to a large number of AWS Identity and Access Management access keys exposed in public assets.
Becau…

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
- **T1656** — Impersonation
- **T1583.006** — Acquire Infrastructure: Web Services

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound email via Amazon SES (amazonses.com envelope) with signature-service / invoice lure

`UC_31_4` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Email
    where (Email.return_addr="*@*.amazonses.com" OR Email.return_addr="*@amazonses.com" OR Email.message_id="*amazonses.com*")
    by Email.src Email.src_user Email.recipient Email.subject Email.return_addr Email.message_id
| `drop_dm_object_name(Email)`
| where match(lower(subject), "docusign|document signed|signature request|please sign|please review and sign|invoice|wire transfer|payment update|banking details|remittance|ach")
| eval src_domain=lower(replace(src, "^.*@", ""))
| where NOT match(src_domain, "(docusign\.(com|net)|adobesign\.com|hellosign\.com|amazonses\.com)$")
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where SenderMailFromDomain endswith "amazonses.com"
   or SenderMailFromAddress endswith "amazonses.com"
   or InternetMessageId has "amazonses.com"
| where Subject matches regex @"(?i)(docusign|document signed|signature request|please (review and )?sign|invoice|wire transfer|payment update|banking details|remittance|\bACH\b)"
| extend DisplayDomain = tolower(SenderFromDomain)
| where DisplayDomain !endswith "docusign.com"
   and DisplayDomain !endswith "docusign.net"
   and DisplayDomain !endswith "adobesign.com"
   and DisplayDomain !endswith "hellosign.com"
   and DisplayDomain !endswith "amazonses.com"
| project Timestamp, NetworkMessageId, InternetMessageId,
          SenderFromAddress, SenderFromDomain,
          SenderMailFromAddress, SenderMailFromDomain,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          AuthenticationDetails, ConfidenceLevel
| order by Timestamp desc
```

### [LLM] Click-through from Amazon SES email to AWS-hosted phishing landing page

`UC_31_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Email
    where (Email.return_addr="*amazonses.com" OR Email.message_id="*amazonses.com*")
    by Email.message_id Email.recipient Email.subject Email.return_addr _time
| `drop_dm_object_name(Email)`
| rename _time as email_time, message_id as msg_id
| join type=inner recipient [
    | tstats summariesonly=t count from datamodel=Web
        where (Web.url="*.amazonaws.com*" OR Web.url="*.cloudfront.net*" OR Web.url="*.awsapps.com*" OR Web.url="*s3.amazonaws.com*")
        by Web.user Web.url Web.dest _time
    | `drop_dm_object_name(Web)`
    | rename _time as click_time, user as recipient
  ]
| eval delay=click_time-email_time
| where delay>=0 AND delay<=600
| table email_time click_time delay recipient subject return_addr msg_id url dest
| sort - click_time
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSec = 600;
let AwsHostedRegex = @"(?i)(\.s3[\.-][a-z0-9-]+\.amazonaws\.com|\.s3\.amazonaws\.com|\.cloudfront\.net|\.amazonaws\.com|\.awsapps\.com|\.execute-api\.[a-z0-9-]+\.amazonaws\.com|\.amplifyapp\.com)";
let SesMail = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    | where SenderMailFromDomain endswith "amazonses.com"
         or InternetMessageId has "amazonses.com"
    | project NetworkMessageId, EmailTime = Timestamp,
              SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject;
let SesUrls = SesMail
    | join kind=inner (EmailUrlInfo | project NetworkMessageId, Url, UrlDomain) on NetworkMessageId
    | where UrlDomain matches regex AwsHostedRegex
         or Url matches regex AwsHostedRegex;
UrlClickEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("ClickAllowed","ClickedThrough")
| join kind=inner SesUrls on $left.NetworkMessageId == $right.NetworkMessageId
| where Timestamp between (EmailTime .. EmailTime + WindowSec * 1s)
| extend DelaySec = datetime_diff('second', Timestamp, EmailTime)
| project ClickTime = Timestamp, EmailTime, DelaySec,
          AccountUpn, IPAddress, IsClickedThrough,
          SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
          Subject, ClickedUrl = Url1, LandingDomain = UrlDomain,
          NetworkMessageId
| order by ClickTime desc
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

Severity classified as **HIGH** based on: 6 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
