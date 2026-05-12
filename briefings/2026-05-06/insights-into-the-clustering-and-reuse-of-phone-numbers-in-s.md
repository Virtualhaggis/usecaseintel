# [MED] Insights into the clustering and reuse of phone numbers in scam emails

**Source:** Cisco Talos
**Published:** 2026-05-06
**Article:** https://blog.talosintelligence.com/insights-into-the-clustering-and-reuse-of-phone-numbers-in-scam-emails/

## Threat Profile

Insights into the clustering and reuse of phone numbers in scam emails 
By 
Omid Mirzaei 
Wednesday, May 6, 2026 06:00
On The Radar
Cisco Talos has recently started to collect and gather intelligence around phone numbers within emails as an additional indicator of compromise (IOC). In this blog, we discuss new insights into in-the-wild phone number reuse in scam emails.  
According to Talos’ observations, the ease of API-driven provisioning makes a few VoIP providers the preferred tool for attac…

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
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1657** — Financial Theft
- **T1566** — Phishing
- **T1598.002** — Phishing for Information: Spearphishing Attachment

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] HEIC/image attachment in inbound email impersonating PayPal/Norton/McAfee/Geek Squad (TOAD callback fraud)

`UC_69_4` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstSeen max(_time) as lastSeen values(Email.subject) as subjects values(Email.file_name) as files values(Email.src_user) as senders from datamodel=Email where (Email.file_name="*.heic" OR Email.file_name="*.heif" OR Email.file_name="*.jfif") AND (Email.subject="*PayPal*" OR Email.subject="*Geek Squad*" OR Email.subject="*Best Buy*" OR Email.subject="*McAfee*" OR Email.subject="*Norton*" OR Email.subject="*LifeLock*") by Email.recipient Email.message_id
| `drop_dm_object_name(Email)`
| where firstSeen > relative_time(now(), "-30d@d")
```

**Defender KQL:**
```kql
// TOAD callback fraud: rare image-format attachments + brand-impersonation subject
let TOADBrands = dynamic(["PayPal","Geek Squad","Best Buy","McAfee","Norton","LifeLock"]);
let RareAttachExt = dynamic(["heic","heif","jfif"]);
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where tolower(FileType) in (RareAttachExt)
   or FileName endswith ".heic" or FileName endswith ".heif" or FileName endswith ".jfif"
| join kind=inner (
    EmailEvents
    | where Timestamp > ago(30d)
    | where EmailDirection == "Inbound"
    | where DeliveryAction in ("Delivered","DeliveredAsSpam")
    | where Subject has_any (TOADBrands)
    | project NetworkMessageId, Subject, SenderFromAddress, SenderMailFromAddress,
              RecipientEmailAddress, DeliveryAction, DeliveryLocation, EmailLanguage
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress,
          RecipientEmailAddress, Subject, FileName, FileType, FileSize,
          DeliveryAction, DeliveryLocation, SHA256
| order by Timestamp desc
```

### [LLM] Inbound TOAD lure: brand-impersonation subject paired with callback business-context phrasing

`UC_69_5` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count dc(Email.recipient) as recipientCount values(Email.subject) as subjects values(Email.file_name) as attachments values(Email.src_user) as senders min(_time) as firstSeen max(_time) as lastSeen from datamodel=Email where ((Email.subject="*PayPal*" OR Email.subject="*Geek Squad*" OR Email.subject="*Best Buy*" OR Email.subject="*McAfee*" OR Email.subject="*Norton*" OR Email.subject="*LifeLock*") AND (Email.subject="*invoice*" OR Email.subject="*subscription*" OR Email.subject="*renewal*" OR Email.subject="*order confirmation*" OR Email.subject="*transaction*" OR Email.subject="*refund*" OR Email.subject="*billing*" OR Email.subject="*purchase*")) by Email.src_user Email.message_id
| `drop_dm_object_name(Email)`
| where recipientCount >= 5
| sort - recipientCount
```

**Defender KQL:**
```kql
// TOAD lure: brand impersonation + callback business context in inbound subject
let TOADBrands = dynamic(["PayPal","Geek Squad","Best Buy","McAfee","Norton","LifeLock"]);
let CallbackContext = dynamic(["invoice","subscription","renewal","order confirmation",
    "transaction","refund","billing","purchase","auto-renewal","order #","receipt"]);
// Known IOC from the campaign — surface explicitly when seen anywhere in subject
let NamedPhonePatterns = dynamic(["804-713-4598","804.713.4598","(804) 713-4598",
    "8047134598","+1 804 713 4598","804 713 4598"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject has_any (TOADBrands)
| where Subject has_any (CallbackContext) or Subject has_any (NamedPhonePatterns)
| extend NamedIOCMatch = iff(Subject has_any (NamedPhonePatterns), "Talos-804-713-block", "")
| summarize MailCount = count(),
            DistinctRecipients = dcount(RecipientEmailAddress),
            DistinctSenders    = dcount(SenderFromAddress),
            SampleSubjects     = make_set(Subject, 8),
            SampleSenders      = make_set(SenderFromAddress, 8),
            FirstSeen          = min(Timestamp),
            LastSeen           = max(Timestamp),
            IOCMatches         = make_set_if(NamedIOCMatch, NamedIOCMatch != "")
            by SenderMailFromDomain, bin(Timestamp, 1d)
// Talos observed +1 804-713-4598 in 117 emails in a single day; threshold tuned conservatively
| where MailCount >= 10 or array_length(IOCMatches) > 0
| order by Timestamp desc, MailCount desc
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

Severity classified as **MED** based on: 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
