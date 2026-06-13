# [CRIT] AI Phishing Is Crushing SOCs with Alert Volume: How to Reduce Tier 1 Overload

**Source:** The Hacker News
**Published:** 2026-06-08
**Article:** https://thehackernews.com/2026/06/ai-phishing-is-crushing-socs-with-alert.html

## Threat Profile

AI Phishing Is Crushing SOCs with Alert Volume: How to Reduce Tier 1 Overload 
 The Hacker News  Jun 08, 2026 Incident Response / Artificial Intelligence 
Phishing has always been a numbers game. AI has turned it into a volume machine.
Attackers can now create convincing emails, fake login pages, and tailored lures in minutes. Every polished message adds another case for Tier 1 to review, another link to inspect, and another alert that cannot be dismissed at a glance.
As the queue grows, a cre…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `13.107.213.44`
- **IPv4 (defanged):** `143.204.203.52`
- **Domain (defanged):** `blog.com`
- **Domain (defanged):** `openvpn.com`
- **Domain (defanged):** `epleyonlineo.za.com`

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
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1656** — Impersonation
- **T1078.004** — Cloud Accounts
- **T1621** — Multi-Factor Authentication Request Generation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Inbound LinkedIn-themed lure with URL chain terminating at AWS CloudFront M365 decoy

`UC_101_7` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
let LookbackDays = 7d;
let LinkedInLureTokens = dynamic(["linkedin","lnkd.in","drive","document","shared file","docusign","review"]);
let PhishHostSuffix = dynamic([".cloudfront.net",".amazonaws.com"]);
let Inbound = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
    | where Subject has_any (LinkedInLureTokens)
         or SenderDisplayName has "linkedin"
         or SenderFromAddress has "linkedin"
    | project NetworkMessageId, EmailTime = Timestamp, Subject,
              SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress;
let UrlsToCloudFront = EmailUrlInfo
    | where Timestamp > ago(LookbackDays)
    | where UrlDomain endswith ".cloudfront.net" or Url has_any (PhishHostSuffix)
    | project NetworkMessageId, Url, UrlDomain;
let ChainedClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | where Url has_any (PhishHostSuffix) or Url has "cloudfront"
    | project ClickTime = Timestamp, NetworkMessageId, AccountUpn, Url, IPAddress, UrlChain;
Inbound
| join kind=inner UrlsToCloudFront on NetworkMessageId
| join kind=inner ChainedClicks on NetworkMessageId
| where RecipientEmailAddress !endswith "gmail.com"
    and RecipientEmailAddress !endswith "yahoo.com"
    and RecipientEmailAddress !endswith "outlook.com"
    and RecipientEmailAddress !endswith "hotmail.com"   // mirror the campaign's corporate-only filter
| project ClickTime, EmailTime,
          DelaySec = datetime_diff('second', ClickTime, EmailTime),
          AccountUpn, RecipientEmailAddress,
          SenderFromAddress, SenderMailFromDomain,
          Subject, Url, UrlDomain, UrlChain, IPAddress
| order by ClickTime desc
```

### Successful M365 sign-in from new IP within 10 min of click to CloudFront-hosted URL

`UC_101_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowMin = 10m;
let Clicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | where Url has "cloudfront" or Url has ".amazonaws.com"
    | project ClickTime = Timestamp, AccountUpn, ClickIP = IPAddress, Url;
let BaselineIPs = AADSignInEventsBeta
    | where Timestamp between (ago(30d) .. ago(LookbackDays))
    | where ErrorCode == 0
    | summarize by AccountUpn, IPAddress;
AADSignInEventsBeta
| where Timestamp > ago(LookbackDays)
| where ErrorCode == 0
| where Application has_any ("Office 365","Microsoft 365","Office Home","OfficeHome")
| join kind=inner Clicks on AccountUpn
| where Timestamp between (ClickTime .. ClickTime + WindowMin)
| join kind=leftanti BaselineIPs on AccountUpn, IPAddress
| project SignInTime = Timestamp, ClickTime,
          DelayMin = datetime_diff('minute', Timestamp, ClickTime),
          AccountUpn, IPAddress, Country, City, UserAgent,
          Application, Url
| order by SignInTime desc
```

### From / Reply-To header domain mismatch with Reply-To on free webmail

`UC_101_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
let LookbackDays = 7d;
let FreeWebmail = dynamic(["gmail.com","yahoo.com","outlook.com","hotmail.com","proton.me","protonmail.com","yandex.com","mail.ru","gmx.com","aol.com","icloud.com","zoho.com"]);
EmailEvents
| where Timestamp > ago(LookbackDays)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| extend ReplyTo = tostring(parse_json(tostring(AdditionalFields)).ReplyTo)
| extend ReplyToDomain = tolower(extract(@"@([A-Za-z0-9.\-]+)", 1, ReplyTo))
| where isnotempty(ReplyToDomain)
| where ReplyToDomain != tolower(SenderFromDomain)
| where ReplyToDomain in (FreeWebmail)
| where SenderFromDomain !in (FreeWebmail)   // From is a brand/corp domain, Reply-To is free mail
| project Timestamp, NetworkMessageId, SenderDisplayName,
          SenderFromAddress, SenderFromDomain,
          ReplyTo, ReplyToDomain,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

### MFA push fatigue: denied MFA followed by successful AAD sign-in within 2 minutes

`UC_101_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSec = 120;
let MfaDenied = AADSignInEventsBeta
    | where Timestamp > ago(LookbackDays)
    | where ErrorCode in (50158, 500121, 50097, 50074)   // MFA challenge denied / not satisfied / device auth required
    | project DenyTime = Timestamp, AccountUpn, IPAddress, Application;
AADSignInEventsBeta
| where Timestamp > ago(LookbackDays)
| where ErrorCode == 0
| join kind=inner MfaDenied on AccountUpn, IPAddress
| where Timestamp between (DenyTime .. DenyTime + WindowSec * 1s)
| project SuccessTime = Timestamp, DenyTime,
          DelaySec = datetime_diff('second', Timestamp, DenyTime),
          AccountUpn, IPAddress, Country, City, UserAgent,
          Application, AppDisplayName
| order by SuccessTime desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `13.107.213.44`, `143.204.203.52`, `blog.com`, `openvpn.com`, `epleyonlineo.za.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
