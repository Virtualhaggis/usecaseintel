# [CRIT] Microsoft Details Phishing Campaign Targeting 35,000 Users Across 26 Countries

**Source:** The Hacker News
**Published:** 2026-05-05
**Article:** https://thehackernews.com/2026/05/microsoft-details-phishing-campaign.html

## Threat Profile

Microsoft Details Phishing Campaign Targeting 35,000 Users Across 26 Countries 
 Ravie Lakshmanan  May 05, 2026 
Microsoft has disclosed details of a large-scale credential theft campaign that has leveraged a combination of code of conduct-themed lures and legitimate email services to direct users to attacker-controlled domains and steal authentication tokens.
The multi-stage campaign, observed between April 14 and 16, 2026, targeted more than 35,000 users across over 13,000 organizations in 2…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1566.002** — Phishing: Spearphishing Link
- **T1557** — Adversary-in-the-Middle
- **T1539** — Steal Web Session Cookie
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556.007** — Modify Authentication Process: Hybrid Identity

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Code of Conduct AiTM phish lure — inbound email by sender, subject, and PDF filename

`UC_56_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Email.subject) as subjects, values(Email.file_name) as attachments, values(Email.recipient) as recipients, values(Email.message_id) as message_ids from datamodel=Email where (Email.src_user IN ("cocpostmaster@cocinternal.com","nationaladmin@gadellinet.com","nationalintegrity@harteprn.com","m365premiumcommunications@cocinternal.com","documentviewer@na.businesshellosign.de") OR Email.src_user IN ("*@cocinternal.com","*@gadellinet.com","*@harteprn.com","*@na.businesshellosign.de") OR Email.subject IN ("*Internal case log issued under conduct policy*","*Reminder: employer opened a non-compliance case log*","*non-compliance case log*") OR Email.file_name IN ("Awareness Case Log File*April 2026.pdf","Awareness Case Log File*pdf")) by Email.src_user, Email.recipient, host
| `drop_dm_object_name(Email)`
| where count > 0
```

**Defender KQL:**
```kql
// Code of Conduct AiTM lure — inbound email match (Microsoft 'Breaking the code', May 2026)
let CocSenders = dynamic(["cocpostmaster@cocinternal.com","nationaladmin@gadellinet.com","nationalintegrity@harteprn.com","m365premiumcommunications@cocinternal.com","documentviewer@na.businesshellosign.de"]);
let CocSenderDomains = dynamic(["cocinternal.com","gadellinet.com","harteprn.com","na.businesshellosign.de"]);
let CocDisplayNames = dynamic(["Internal Regulatory COC","Workforce Communications","Team Conduct Report"]);
let CocSubjectFragments = dynamic(["Internal case log issued under conduct policy","Reminder: employer opened a non-compliance case log","non-compliance case log","issued under conduct policy"]);
let CocAttachmentSHA256 = dynamic(["5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6","B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD","11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D"]);
let HitMail = EmailEvents
    | where Timestamp > ago(30d)
    | where EmailDirection == "Inbound"
    | where SenderFromAddress in~ (CocSenders)
        or SenderMailFromAddress in~ (CocSenders)
        or SenderFromDomain in~ (CocSenderDomains)
        or SenderMailFromDomain in~ (CocSenderDomains)
        or SenderDisplayName in~ (CocDisplayNames)
        or Subject has_any (CocSubjectFragments)
    | project Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName,
              SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction,
              DeliveryLocation, ThreatTypes;
HitMail
| join kind=leftouter (
    EmailAttachmentInfo
    | where Timestamp > ago(30d)
    | where FileName has "Awareness Case Log File" and FileName endswith ".pdf"
        or SHA256 in (CocAttachmentSHA256)
    | project NetworkMessageId, AttachmentName = FileName, AttachmentSHA256 = SHA256, FileSize
  ) on NetworkMessageId
| project Timestamp, SenderFromAddress, SenderDisplayName, SenderFromDomain,
          RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation,
          AttachmentName, AttachmentSHA256, NetworkMessageId
| order by Timestamp desc
```

### [LLM] Workstation egress to Code of Conduct AiTM landing-page domains (compliance-protectionoutlook[.]de et al.)

`UC_56_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Web.url) as urls, values(Web.user) as users, values(Web.dest) as dest, min(_time) as first_seen, max(_time) as last_seen from datamodel=Web where Web.url IN ("*compliance-protectionoutlook.de*","*acceptable-use-policy-calendly.de*","*cocinternal.com*","*gadellinet.com*","*harteprn.com*","*na.businesshellosign.de*") by Web.src, Web.user, host
| `drop_dm_object_name(Web)`
| append [
    | tstats summariesonly=true count, values(DNS.query) as queries, min(_time) as first_seen, max(_time) as last_seen from datamodel=Network_Resolution where DNS.query IN ("*compliance-protectionoutlook.de","*acceptable-use-policy-calendly.de","*cocinternal.com","*gadellinet.com","*harteprn.com","*na.businesshellosign.de") by DNS.src, host
    | `drop_dm_object_name(DNS)`
  ]
| stats sum(count) as hits, values(urls) as urls, values(queries) as queries, min(first_seen) as first_seen, max(last_seen) as last_seen by src, user, host
```

**Defender KQL:**
```kql
// Code of Conduct AiTM campaign — egress to Microsoft-published phishing/sender domains
let CocDomains = dynamic(["compliance-protectionoutlook.de","acceptable-use-policy-calendly.de","cocinternal.com","gadellinet.com","harteprn.com","na.businesshellosign.de"]);
let Clicks = UrlClickEvents
    | where Timestamp > ago(30d)
    | where Url has_any (CocDomains)
    | project Timestamp, AccountUpn, Url, IPAddress, ActionType, NetworkMessageId,
              IsClickedThrough, Source = "UrlClickEvents";
let NetConn = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (CocDomains)
        or tostring(parse_url(RemoteUrl).Host) has_any (CocDomains)
    | project Timestamp, DeviceName, AccountUpn = InitiatingProcessAccountUpn,
              Url = RemoteUrl, RemoteIP, RemotePort, ActionType,
              InitiatingProcessFileName, Source = "DeviceNetworkEvents";
let DnsQueries = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where Q has_any (CocDomains)
    | project Timestamp, DeviceName, AccountUpn = InitiatingProcessAccountUpn,
              Url = Q, InitiatingProcessFileName, Source = "DeviceEvents-DNS";
union Clicks, NetConn, DnsQueries
| order by Timestamp desc
```

### [LLM] AiTM token theft — successful Entra ID sign-in from new IP within 30 min of clicking COC phishing URL

`UC_56_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as click_time, values(Web.url) as click_url from datamodel=Web where Web.url IN ("*compliance-protectionoutlook.de*","*acceptable-use-policy-calendly.de*","*cocinternal.com*","*gadellinet.com*","*harteprn.com*") by Web.user
| `drop_dm_object_name(Web)`
| rename user as Authentication.user
| join type=inner Authentication.user [
    | tstats summariesonly=true count, values(Authentication.src) as new_src, values(Authentication.user_agent) as new_ua, min(_time) as signin_time from datamodel=Authentication where Authentication.action="success" Authentication.app="azure_active_directory" earliest=-30d by Authentication.user, Authentication.src
    | `drop_dm_object_name(Authentication)`
  ]
| where signin_time >= click_time AND signin_time <= click_time + 1800
| join type=left user [
    | tstats summariesonly=true count from datamodel=Authentication where Authentication.action="success" Authentication.app="azure_active_directory" earliest=-60d latest=-1d by Authentication.user, Authentication.src
    | `drop_dm_object_name(Authentication)`
    | stats values(src) as historical_src by user
  ]
| eval is_new_ip = if(isnull(historical_src) OR NOT match(mvjoin(historical_src,","),src), 1, 0)
| where is_new_ip=1
| table click_time, signin_time, user, click_url, src, new_ua, historical_src
```

**Defender KQL:**
```kql
// AiTM token theft — successful AAD sign-in from new IP within 30m of clicking the COC phishing URL
let LookbackDays = 14d;
let BaselineDays = 60d;
let WindowAfterClick = 30m;
let CocDomains = dynamic(["compliance-protectionoutlook.de","acceptable-use-policy-calendly.de","cocinternal.com","gadellinet.com","harteprn.com","na.businesshellosign.de"]);
let CocClicks = UrlClickEvents
    | where Timestamp > ago(LookbackDays)
    | where Url has_any (CocDomains)
    | project ClickTime = Timestamp, AccountUpn, ClickIP = IPAddress, ClickUrl = Url;
let UserBaseline = AADSignInEventsBeta
    | where Timestamp between (ago(BaselineDays) .. ago(LookbackDays))
    | where ErrorCode == 0
    | summarize KnownIPs = make_set(IPAddress, 5000), KnownCountries = make_set(Country) by AccountUpn;
AADSignInEventsBeta
| where Timestamp > ago(LookbackDays)
| where ErrorCode == 0
| project SignInTime = Timestamp, AccountUpn, SignInIP = IPAddress, Country, City,
          Application, ApplicationId, UserAgent, ClientAppUsed, RiskLevelDuringSignIn,
          ConditionalAccessStatus, IsAnonymousProxy
| join kind=inner CocClicks on AccountUpn
| where SignInTime between (ClickTime .. ClickTime + WindowAfterClick)
| join kind=leftouter UserBaseline on AccountUpn
| extend NewIP = iif(isempty(KnownIPs) or not(set_has_element(KnownIPs, SignInIP)), true, false)
| extend NewCountry = iif(isempty(KnownCountries) or not(set_has_element(KnownCountries, Country)), true, false)
| where NewIP == true or NewCountry == true or IsAnonymousProxy == true
| project ClickTime, SignInTime,
          DelayMin = datetime_diff('minute', SignInTime, ClickTime),
          AccountUpn, ClickUrl, ClickIP, SignInIP, Country, City,
          Application, UserAgent, ClientAppUsed, ConditionalAccessStatus,
          NewIP, NewCountry, IsAnonymousProxy
| order by SignInTime desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
