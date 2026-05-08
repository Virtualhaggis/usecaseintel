# [CRIT] Scammers Use Short-Lived VoIP Numbers and Reuse Windows to Defeat Reputation-Based Blocking

**Source:** Cyber Security News
**Published:** 2026-05-07
**Article:** https://cybersecuritynews.com/scammers-use-short-lived-voip-numbers-and-reuse-windows/

## Threat Profile

Home Cyber Security News 
Scammers Use Short-Lived VoIP Numbers and Reuse Windows to Defeat Reputation-Based Blocking 
By Tushar Subhra Dutta 
May 7, 2026 
Phone-based scams are evolving faster than most security filters can keep up with. Attackers are now leaning heavily on Voice over Internet Protocol (VoIP) numbers that disappear before detection systems can flag them, leaving users exposed and defenders scrambling.
These scam campaigns arrive through email, where attackers embed phone number…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1656** — Impersonation
- **T1566** — Phishing
- **T1583.003** — Acquire Infrastructure: Virtual Private Server

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] HEIC attachment in inbound email impersonating PayPal/Geek Squad/McAfee/Norton (TOAD callback lure)

`UC_21_3` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Email.file_name) as file_name values(Email.subject) as subject values(Email.recipient) as recipient values(Email.src_user) as src_user from datamodel=Email where Email.action=delivered Email.is_inbound=true (Email.file_name="*.heic" OR Email.file_name="*.HEIC" OR Email.file_name="*.heif") by Email.message_id Email.src_user Email.recipient
| `drop_dm_object_name(Email)`
| eval brand_hit=if(match(lower(subject), "paypal|geek\s*squad|mcafee|norton|lifelock|amazon|apple|best\s*buy|microsoft|coinbase"),1,0)
| where brand_hit=1
| eval reason="HEIC attachment + brand-impersonation subject = TOAD callback lure (Cisco Talos Feb-Mar 2025)"
| table firstTime lastTime src_user recipient subject file_name reason
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// HEIC attachment in inbound email + brand-impersonation subject = TOAD callback lure
let BrandRegex = @"(?i)paypal|geek\s*squad|mcafee|norton|lifelock|amazon|apple|best\s*buy|microsoft\s+(store|365)|coinbase|invoice|order\s+confirm|subscription\s+renew|antivirus|auto[-\s]*renew";
let HeicMessages = EmailAttachmentInfo
    | where Timestamp > ago(7d)
    | where FileType in~ ("heic","heif") or FileName endswith ".heic" or FileName endswith ".heif"
    | project NetworkMessageId, AttachmentFileName = FileName, AttachmentFileType = FileType, AttachmentSHA256 = SHA256;
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject matches regex BrandRegex
| join kind=inner HeicMessages on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, SenderFromDomain,
          RecipientEmailAddress, Subject, AttachmentFileName, AttachmentFileType, AttachmentSHA256,
          DeliveryAction, DeliveryLocation, AuthenticationDetails
| order by Timestamp desc
```

### [LLM] Same VoIP callback number recurring across unrelated lures within Talos 14-day cool-down

`UC_21_4` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(Email.subject) as subjects values(Email.src_user) as senders values(Email.recipient) as recipients values(Email.src_user_domain) as sender_domains from datamodel=Email where Email.action=delivered Email.is_inbound=true by Email.subject
| `drop_dm_object_name(Email)`
| rex field=subject "(?<phone_raw>(?:\+?1[\s\.\-]?)?\(?[2-9]\d{2}\)?[\s\.\-]?[2-9]\d{2}[\s\.\-]?\d{4})"
| where isnotnull(phone_raw)
| eval phone=replace(phone_raw, "[^0-9]", "")
| eval phone=if(len(phone)==10, "1".phone, phone)
| eval lure=case(match(lower(subject),"order\s+(confirm|#|number|placed)"),"OrderConfirmation", match(lower(subject),"subscription|auto[-\s]*renew|renewal|expir"),"SubscriptionRenewal", match(lower(subject),"invoice|payment|charge|refund|transaction"),"FinancialAlert", match(lower(subject),"support|geek\s*squad|antivirus|mcafee|norton"),"TechSupport", match(lower(subject),"delivery|shipped|package|tracking"),"Shipping", true(),"Other")
| stats min(firstSeen) as firstSeen max(lastSeen) as lastSeen dc(lure) as distinct_lures values(lure) as lure_buckets dc(subject) as distinct_subjects values(subject) as sample_subjects dc(sender_domains) as distinct_sender_domains values(sender_domains) as sender_domains dc(recipients) as recipient_count sum(count) as message_count by phone
| where distinct_lures>=2 AND distinct_sender_domains>=2 AND (lastSeen-firstSeen)<=1209600
| eval reason="VoIP number reused across ".distinct_lures." lure themes from ".distinct_sender_domains." sender domains within 14d (Talos median number lifespan)"
| convert ctime(firstSeen) ctime(lastSeen)
| sort - distinct_lures
```

**Defender KQL:**
```kql
// VoIP-number reuse across unrelated lures - cluster on extracted phone digits over 14d
let Lookback = 14d;
let PhoneRegex = @"(?:\+?1[\s\.\-]?)?\(?[2-9]\d{2}\)?[\s\.\-]?[2-9]\d{2}[\s\.\-]?\d{4}";
EmailEvents
| where Timestamp > ago(Lookback)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject matches regex PhoneRegex
| extend PhoneRaw = extract(PhoneRegex, 0, Subject)
| extend Phone = replace_regex(PhoneRaw, @"[^0-9]", "")
| extend Phone = iff(strlen(Phone) == 10, strcat("1", Phone), Phone)
| where strlen(Phone) == 11
| extend LureBucket = case(
    Subject matches regex @"(?i)order\s+(confirm|#|number|placed)",          "OrderConfirmation",
    Subject matches regex @"(?i)subscription|auto[-\s]*renew|renewal|expir",  "SubscriptionRenewal",
    Subject matches regex @"(?i)invoice|payment|charge|refund|transaction",   "FinancialAlert",
    Subject matches regex @"(?i)support|tech\s+support|geek\s*squad|antivirus|mcafee|norton", "TechSupport",
    Subject matches regex @"(?i)delivery|shipped|package|tracking",           "Shipping",
    "Other")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            DistinctLures = dcount(LureBucket),
            LureBuckets = make_set(LureBucket),
            DistinctSubjects = dcount(Subject),
            SampleSubjects = make_set(Subject, 10),
            DistinctSenderDomains = dcount(SenderFromDomain),
            SenderDomains = make_set(SenderFromDomain, 20),
            RecipientCount = dcount(RecipientEmailAddress),
            MessageCount = count()
            by Phone
| where DistinctLures >= 2 and DistinctSenderDomains >= 2
| extend WindowDays = datetime_diff('day', LastSeen, FirstSeen)
| where WindowDays <= 14
| order by DistinctLures desc, MessageCount desc
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

Severity classified as **CRIT** based on: 5 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
