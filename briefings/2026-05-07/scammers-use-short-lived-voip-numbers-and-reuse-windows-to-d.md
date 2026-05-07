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
These scam campaigns arrive through email, where attackers embed phon…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1036** — Masquerading
- **T1583.003** — Acquire Infrastructure: Virtual Private Server
- **T1656** — Impersonation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound TOAD email with HEIC attachment impersonating PayPal/Geek Squad/McAfee/Norton

`UC_1_3` · phase: **delivery** · confidence: **High**

**Defender KQL:**
```kql
// TOAD: HEIC attachment + named brand impersonation (Cisco Talos, Feb-Mar 2025)
let ToadBrands = dynamic(["paypal","geek squad","geeksquad","best buy","mcafee","norton","lifelock"]);
let LureTerms = dynamic(["renewal","refund","invoice","subscription","order","charge","auto-renew","cancellation","unauthorized","purchase","receipt","confirmation"]);
let HeicAttachments = EmailAttachmentInfo
    | where Timestamp > ago(7d)
    | where FileType =~ "HEIC" or FileName endswith ".heic" or FileName endswith ".heif"
    | project NetworkMessageId, FileName, FileType, FileSize, AttSha256 = SHA256;
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where Subject has_any (ToadBrands) or SenderDisplayName has_any (ToadBrands)
| where Subject has_any (LureTerms)                                  // lure language pairs with brand
| where SenderFromDomain !endswith "paypal.com"                      // exclude legit paypal.com
    and SenderFromDomain !endswith "bestbuy.com"
    and SenderFromDomain !endswith "mcafee.com"
    and SenderFromDomain !endswith "norton.com"
    and SenderFromDomain !endswith "nortonlifelock.com"
    and SenderFromDomain !endswith "lifelock.com"
| join kind=inner HeicAttachments on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, SenderDisplayName,
          RecipientEmailAddress, Subject, FileName, FileType, FileSize, AttSha256, DeliveryAction
| order by Timestamp desc
```

### [LLM] TOAD callback number recycled across unrelated lure subjects (sequential DID reuse hunt)

`UC_1_4` · phase: **delivery** · confidence: **Medium**

**Defender KQL:**
```kql
// Hunt: same toll-free CPaaS DID recycled across distinct senders + lure subjects
// Article: 14-day median number lifespan; 68 of 1,962 numbers reused on consecutive days;
// same number reappears in unrelated lures (order confirmation, subscription, financial alert).
let LookbackDays = 14d;          // matches Talos's observed median number lifespan
let ToadBrands = dynamic(["paypal","geek squad","geeksquad","best buy","mcafee","norton","lifelock","docusign","microsoft 365","microsoft365"]);
let PhoneRx = @"(?i)(?:\+?1[\s.\-]?)?\(?(8(?:00|33|44|55|66|77|88))\)?[\s.\-]?(\d{3})[\s.\-]?(\d{4})";
EmailEvents
| where Timestamp > ago(LookbackDays)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| extend Phone = extract(PhoneRx, 0, Subject)
| where isnotempty(Phone)
| extend PhoneNorm = replace_regex(Phone, @"[\s.\-\(\)\+]", "")
| extend PhoneNorm = iif(strlen(PhoneNorm) == 11 and PhoneNorm startswith "1", substring(PhoneNorm, 1, 10), PhoneNorm)
| where strlen(PhoneNorm) == 10
| extend BrandHit = iif(Subject has_any (ToadBrands), 1, 0)
| summarize
    DistinctSenderDomains = dcount(SenderFromDomain),
    DistinctSenders       = dcount(SenderFromAddress),
    DistinctSubjects      = dcount(Subject),
    DistinctRecipients    = dcount(RecipientEmailAddress),
    BrandsTouched         = make_set_if(Subject, BrandHit == 1, 8),
    SampleSubjects        = make_set(Subject, 6),
    SampleSenders         = make_set(SenderFromAddress, 6),
    FirstSeen             = min(Timestamp),
    LastSeen              = max(Timestamp),
    DaysActive            = dcount(bin(Timestamp, 1d)),
    TotalEmails           = count()
  by PhoneNorm
// reuse-pattern thresholds derived from Talos: 68/1962 (~3.5%) numbers reused across
// consecutive days; multi-sender + multi-subject clustering is the high-fidelity signal
| where DistinctSenderDomains >= 3 and DistinctSubjects >= 3 and TotalEmails >= 5
| order by DistinctSenderDomains desc, TotalEmails desc
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

Severity classified as **CRIT** based on: 5 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
