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
- **T1598.003** — Phishing for Information: Spearphishing Link
- **T1656** — Impersonation
- **T1583.001** — Acquire Infrastructure: Domains

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### LinkedIn file-share URL click chain redirecting to AWS CloudFront-hosted Microsoft 365 credential capture

`UC_101_7` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Email.recipient) as recipient values(Email.url) as url values(Email.url_chain) as url_chain from datamodel=Email where Email.direction="inbound" Email.delivery_action="delivered" (Email.url="*linkedin.com/dms/*" OR Email.url="*linkedin.com/in/*" OR Email.url="*linkedin.com/feed/*" OR Email.url="*lnkd.in/*") (Email.url_chain="*cloudfront.net*" OR Email.url_chain="*amazonaws.com*") by Email.sender Email.subject Email.recipient | `drop_dm_object_name(Email)` | where match(url_chain,"(?i)(microsoft|office365|login|m365|outlook)") | sort - lastTime
```

**Defender KQL:**
```kql
// Article: ANY.RUN case study — LinkedIn share link -> CloudFront-hosted fake M365 login page
let LookbackDays = 7d;
let LinkedInLures = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
    | join kind=inner (
        EmailUrlInfo
        | where Url has_any ("linkedin.com/dms/", "linkedin.com/in/", "linkedin.com/feed/", "lnkd.in/")
        | project NetworkMessageId, LureUrl = Url, UrlDomain
      ) on NetworkMessageId
    | project NetworkMessageId, EmailTime = Timestamp, SenderFromAddress,
              RecipientEmailAddress, Subject, LureUrl;
UrlClickEvents
| where Timestamp > ago(LookbackDays)
| where ActionType in ("ClickAllowed","ClickedThrough")
| extend ChainStr = tostring(UrlChain)
| where ChainStr has_any ("cloudfront.net", ".s3.amazonaws.com", "cloudfront.amazonaws.com")
| where ChainStr matches regex @"(?i)(microsoft|office365|outlook|m365|login\.microsoftonline)"
   or Url matches regex @"(?i)(microsoft|office365|outlook|m365|login\.microsoftonline)"
| join kind=inner LinkedInLures on NetworkMessageId
| project Timestamp, EmailTime, AccountUpn, SenderFromAddress, Subject,
          LureUrl, ClickedUrl = Url, UrlChain, IsClickedThrough, IPAddress
| order by Timestamp desc
```

### Safe Links click-through to a tenant-first-seen domain (short-lived-domain hunt)

`UC_101_8` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` values(Email.url) as urls min(_time) as firstSeen from datamodel=Email where Email.url_click_action IN ("ClickAllowed","ClickedThrough") earliest=-30d@d latest=-1h by Email.url_domain | rename Email.url_domain as baseline_domain | append [ | tstats `summariesonly` count values(Email.recipient) as recipient values(Email.url) as url min(_time) as firstSeen from datamodel=Email where Email.url_click_action="ClickedThrough" earliest=-1h by Email.url_domain | rename Email.url_domain as recent_domain ] | stats values(*) as * by recent_domain | where isnull(baseline_domain) | sort - firstSeen
```

**Defender KQL:**
```kql
// Article-grounded: AI phishing relies on URLs with no reputation history; flag click-throughs to tenant-first-seen domains
let BaselineDays = 30d;
let RecentHours = 4h;
let Baseline = UrlClickEvents
    | where Timestamp between (ago(BaselineDays) .. ago(RecentHours))
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | extend BaselineDomain = tostring(parse_url(Url).Host)
    | where isnotempty(BaselineDomain)
    | summarize BaselineHits = count() by BaselineDomain
    | where BaselineHits >= 2;        // 2+ historical clicks = not first-seen
UrlClickEvents
| where Timestamp > ago(RecentHours)
| where ActionType == "ClickedThrough"   // user bypassed the warning - higher fidelity than ClickAllowed alone
| extend ClickDomain = tostring(parse_url(Url).Host)
| where isnotempty(ClickDomain)
| where ClickDomain !endswith "microsoft.com"
    and ClickDomain !endswith "office.com"
    and ClickDomain !endswith "office365.com"
    and ClickDomain !endswith "sharepoint.com"
    and ClickDomain !endswith "linkedin.com"
| join kind=leftanti Baseline on $left.ClickDomain == $right.BaselineDomain
| project Timestamp, AccountUpn, Url, ClickDomain, IPAddress, ThreatTypes, DetectionMethods, NetworkMessageId
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

Severity classified as **CRIT** based on: IOCs present, 9 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
