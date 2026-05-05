# [CRIT] Attackers Abuse Amazon SES to Send Authenticated Phishing Emails That Bypass Security

**Source:** Cyber Security News
**Published:** 2026-05-05
**Article:** https://cybersecuritynews.com/attackers-abuse-amazon-ses/

## Threat Profile

Home Cyber Security News 
Attackers Abuse Amazon SES to Send Authenticated Phishing Emails That Bypass Security 
By Tushar Subhra Dutta 
May 5, 2026 
Threat actors are increasingly turning to Amazon’s own cloud email infrastructure to deliver phishing messages that look completely genuine, passing every standard security check along the way.
Phishing has always been about deception. Attackers craft emails designed to look real, hoping recipients will trust what they see and hand over their crede…

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
- **T1195.002** — Compromise Software Supply Chain
- **T1566.002** — Phishing: Spearphishing Link
- **T1656** — Impersonation
- **T1583.006** — Acquire Infrastructure: Web Services
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1534** — Internal Spearphishing

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound email routed via Amazon SES impersonating Docusign brand

`UC_13_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(All_Email.src_user) as sender values(All_Email.recipient) as recipient values(All_Email.subject) as subject values(All_Email.message_id) as message_id from datamodel=Email where All_Email.message_id="*amazonses.com*" (All_Email.subject="*DocuSign*" OR All_Email.subject="*Docusign*" OR All_Email.subject="*please sign*" OR All_Email.subject="*review and sign*" OR All_Email.subject="*document for signature*" OR All_Email.subject="*completed agreement*") NOT (All_Email.src_user="*@docusign.com" OR All_Email.src_user="*@docusign.net" OR All_Email.src_user="*@docusign.eu") by All_Email.src_user All_Email.recipient All_Email.subject All_Email.message_id
| `drop_dm_object_name("All_Email")`
| where firstSeen > relative_time(now(), "-7d@d")
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where InternetMessageId has "amazonses.com"   // Securelist: SES Message-ID always carries this suffix
| where Subject has_any ("DocuSign","Docusign","please sign","review and sign","document for signature","completed agreement","signature requested")
| where SenderFromDomain !endswith "docusign.com"
    and SenderFromDomain !endswith "docusign.net"
    and SenderFromDomain !endswith "docusign.eu"
    and SenderMailFromDomain !endswith "docusign.com"
    and SenderMailFromDomain !endswith "docusign.net"
| project Timestamp, NetworkMessageId, InternetMessageId, SenderFromAddress, SenderFromDomain, SenderMailFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, AuthenticationDetails
| order by Timestamp desc
```

### [LLM] User click on amazonaws.com-hosted credential page delivered via Amazon SES email

`UC_13_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Email where All_Email.message_id="*amazonses.com*" by All_Email.message_id All_Email.recipient All_Email.subject All_Email.src_user _time
| `drop_dm_object_name("All_Email")`
| rename _time as email_time
| join type=inner recipient [
    | tstats summariesonly=true count from datamodel=Web where (Web.url="*amazonaws.com*" OR Web.url="*s3.amazonaws.com*" OR Web.url="*cloudfront.net*") by Web.user Web.url Web.dest _time
    | `drop_dm_object_name("Web")`
    | rename user as recipient _time as click_time
  ]
| eval delay_sec=click_time-email_time
| where delay_sec>=0 AND delay_sec<=86400
| table email_time click_time delay_sec recipient src_user subject message_id url dest
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let SES_Emails =
    EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    | where InternetMessageId has "amazonses.com"
    | project NetworkMessageId, EmailTime = Timestamp, SenderFromAddress, RecipientEmailAddress, Subject;
let SES_AwsLinks =
    SES_Emails
    | join kind=inner (
        EmailUrlInfo
        | where Timestamp > ago(LookbackDays)
        | where UrlDomain endswith "amazonaws.com"
            or UrlDomain endswith "awsapps.com"
            or UrlDomain endswith "cloudfront.net"
            or UrlDomain endswith "awsstatic.com"
        | project NetworkMessageId, Url, UrlDomain
    ) on NetworkMessageId;
UrlClickEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("ClickAllowed","ClickedThrough")
| join kind=inner SES_AwsLinks on $left.Url == $right.Url
| extend DelaySec = datetime_diff('second', Timestamp, EmailTime)
| where DelaySec between (0 .. 86400)
| project ClickTime = Timestamp, EmailTime, DelaySec, AccountUpn, IPAddress,
          IsClickedThrough, Url, UrlDomain, SenderFromAddress, Subject, NetworkMessageId
| order by ClickTime desc
```

### [LLM] BEC pattern: Amazon SES inbound mail with PDF attachment and finance/wire-transfer subject

`UC_13_7` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Email.src_user) as sender values(All_Email.recipient) as recipient values(All_Email.subject) as subject values(All_Email.file_name) as file_name values(All_Email.file_hash) as file_hash from datamodel=Email where All_Email.message_id="*amazonses.com*" (All_Email.subject="*invoice*" OR All_Email.subject="*wire transfer*" OR All_Email.subject="*payment*" OR All_Email.subject="*remittance*" OR All_Email.subject="*ACH*" OR All_Email.subject="*updated banking*" OR All_Email.subject="*bank details*" OR All_Email.subject="*payment instructions*" OR All_Email.subject="*overdue*") (All_Email.file_name="*.pdf" OR All_Email.file_extension="pdf") by All_Email.message_id _time
| `drop_dm_object_name("All_Email")`
| where _time > relative_time(now(), "-14d@d")
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let FinanceTerms = dynamic(["invoice","wire transfer","payment","remittance","ACH","updated banking","bank details","payment instructions","overdue","vendor account","new account"]);
let SES_Inbound =
    EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    | where InternetMessageId has "amazonses.com"
    | where AttachmentCount >= 1
    | where UrlCount == 0   // Securelist BEC variant: PDF only, no malicious URLs / QR codes
    | where Subject has_any (FinanceTerms)
    | project NetworkMessageId, Timestamp, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, AttachmentCount, UrlCount;
SES_Inbound
| join kind=inner (
    EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where FileType =~ "pdf" or FileName endswith ".pdf"
) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress,
          Subject, FileName, FileType, FileSize, SHA256, MalwareFilterVerdict, NetworkMessageId
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

### Trusted vendor binary / installer launching unusual children

`UC_SUPPLY_CHAIN` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.parent_process_name IN ("setup.exe","installer.exe","update.exe")
      AND Processes.process_name IN ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
    by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name, Processes.process
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
