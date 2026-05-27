# [CRIT] Hackers Abuse Trusted Google Domains to Hide Phishing Links From Email Gateways

**Source:** Cyber Security News
**Published:** 2026-05-27
**Article:** https://cybersecuritynews.com/hackers-abuse-trusted-google-domains/

## Threat Profile

Home Cyber Security News 
Hackers Abuse Trusted Google Domains to Hide Phishing Links From Email Gateways 
By Tushar Subhra Dutta 
May 27, 2026 
Phishing attacks are nothing new, but attackers keep finding smarter ways to stay one step ahead of security tools. 
The latest campaign doing the rounds is a stark reminder that trust, especially the kind organizations place in big-name tech platforms, can be turned into a weapon. 
Hackers are now hiding malicious links inside a chain of legitimate Goo…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `vazquezfleytas.com`
- **Domain (defanged):** `edificiocristal.pt`
- **Domain (defanged):** `velvorra.com`
- **Domain (defanged):** `furqanmustafa.com`
- **Domain (defanged):** `unitedtechnofzmlogies.vu`
- **Domain (defanged):** `cloudbemismanufacturingcompanygroup.rydezyhrsysteminc.vu`
- **Domain (defanged):** `servicetriumphgroupsimplyappraisals.spectrhwqumbrands.vu`
- **Domain (defanged):** `cloudgillettebrandberkshirehathaway.rtzcoekdrporation.vu`
- **Domain (defanged):** `odahlzr5lm.reliabilityinoperations.de`
- **Domain (defanged):** `staiwooje.app`
- **Domain (defanged):** `link-form-unj9.p-sm7rw6ru.workers.dev`
- **Domain (defanged):** `data-cloud-ofe8.p-8yejy42o.workers.dev`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1102** — Web Service
- **T1027** — Obfuscated Files or Information
- **T1621** — Multi-Factor Authentication Request Generation
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Inbound email with nested Google redirector chain (meet.google.com/linkredirect → google.com/url → adservice.google.com)

`UC_7_6` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Email.subject) as subject values(All_Email.src_user) as sender values(All_Email.recipient) as recipient values(All_Email.url) as url from datamodel=Email where (All_Email.url="*meet.google.com/linkredirect*" OR All_Email.url="*adservice.google.com*" OR (All_Email.url="*google.com/url?*" AND (All_Email.url="*workers.dev*" OR All_Email.url="*.vu/*" OR All_Email.url="*staiwooje.app*" OR All_Email.url="*vazquezfleytas*" OR All_Email.url="*edificiocristal*" OR All_Email.url="*velvorra*" OR All_Email.url="*furqanmustafa*"))) by All_Email.recipient All_Email.src_user All_Email.message_id | `drop_dm_object_name(All_Email)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SuspectUrls = EmailUrlInfo
| where Timestamp > ago(14d)
| where Url has_any ("meet.google.com/linkredirect", "adservice.google.com.ph", "adservice.google.com")
   or (Url has "google.com/url" and Url has_any ("workers.dev",".vu/",".pt/","staiwooje.app","vazquezfleytas","edificiocristal","velvorra","furqanmustafa","unitedtechnofzmlogies","rydezyhrsysteminc","spectrhwqumbrands","rtzcoekdrporation","reliabilityinoperations"));
SuspectUrls
| join kind=inner (EmailEvents | where Timestamp > ago(14d) | project NetworkMessageId, Subject, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, DeliveryAction, DeliveryLocation, ThreatTypes) on NetworkMessageId
| where DeliveryAction != "Blocked"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromDomain, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryAction, DeliveryLocation, ThreatTypes
| order by Timestamp desc
```

### [LLM] Endpoint network/DNS to KnowBe4-tracked phishing IOCs (Cloudflare Workers + .vu/.pt/.app landing domains)

`UC_7_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.dest) as dest from datamodel=Web where (Web.url="*link-form-unj9.p-sm7rw6ru.workers.dev*" OR Web.url="*data-cloud-ofe8.p-8yejy42o.workers.dev*" OR Web.dest="vazquezfleytas.com" OR Web.dest="edificiocristal.pt" OR Web.dest="velvorra.com" OR Web.dest="furqanmustafa.com" OR Web.dest="unitedtechnofzmlogies.vu" OR Web.dest="staiwooje.app" OR Web.dest="*.rydezyhrsysteminc.vu" OR Web.dest="*.spectrhwqumbrands.vu" OR Web.dest="*.rtzcoekdrporation.vu" OR Web.dest="*.reliabilityinoperations.de") by Web.src Web.user Web.dest Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let IocDomains = dynamic(["vazquezfleytas.com","edificiocristal.pt","velvorra.com","furqanmustafa.com","unitedtechnofzmlogies.vu","rydezyhrsysteminc.vu","spectrhwqumbrands.vu","rtzcoekdrporation.vu","reliabilityinoperations.de","staiwooje.app","link-form-unj9.p-sm7rw6ru.workers.dev","data-cloud-ofe8.p-8yejy42o.workers.dev"]);
let IocHits = DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (IocDomains)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort;
let ClickHits = UrlClickEvents
| where Timestamp > ago(30d)
| where Url has_any (IocDomains)
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough;
union IocHits, ClickHits
| order by Timestamp desc
```

### [LLM] Microsoft Entra device-code authentication flow — first-seen for user (potential device-code phishing relay)

`UC_7_8` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.app) as app from datamodel=Authentication where Authentication.signature="UserLoggedIn" Authentication.authentication_method="deviceCode" Authentication.action="success" by Authentication.user | `drop_dm_object_name(Authentication)` | join type=left user [| tstats `summariesonly` count as priorDeviceCode from datamodel=Authentication where Authentication.signature="UserLoggedIn" Authentication.authentication_method="deviceCode" earliest=-60d@d latest=-7d@d by Authentication.user | `drop_dm_object_name(Authentication)`] | where isnull(priorDeviceCode) OR priorDeviceCode=0 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let Lookback = 7d;
let Baseline = 60d;
let PriorDeviceCodeUsers = AADSignInEventsBeta
    | where Timestamp between (ago(Baseline) .. ago(Lookback))
    | where AuthenticationProcessingDetails has "Device Code" or AuthenticationDetails has "deviceCode"
    | summarize by AccountObjectId;
AADSignInEventsBeta
| where Timestamp > ago(Lookback)
| where AuthenticationProcessingDetails has "Device Code" or AuthenticationDetails has "deviceCode"
| where ErrorCode == 0
| join kind=leftanti PriorDeviceCodeUsers on AccountObjectId
| extend DeviceTrust = tostring(parse_json(tostring(AuthenticationProcessingDetails))[0])
| project Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, City, UserAgent, ClientAppUsed, Application, ApplicationId, ResourceDisplayName, DeviceTrustType, IsCompliantUser, AuthenticationProcessingDetails
| order by Timestamp desc
```

### [LLM] Click on Google nested-redirector or KnowBe4 IOC followed by device-code sign-in within 60 minutes for the same user

`UC_7_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as clickTime values(Web.url) as clickedUrl from datamodel=Web where (Web.url="*meet.google.com/linkredirect*" OR Web.url="*adservice.google.com*" OR Web.url="*google.com/url*" OR Web.url="*workers.dev*" OR Web.url="*vazquezfleytas*" OR Web.url="*edificiocristal*" OR Web.url="*velvorra*" OR Web.url="*staiwooje.app*") by Web.user | `drop_dm_object_name(Web)` | rename user as victim | join type=inner victim [| tstats `summariesonly` count min(_time) as signInTime from datamodel=Authentication where Authentication.signature="UserLoggedIn" Authentication.authentication_method="deviceCode" Authentication.action="success" by Authentication.user | `drop_dm_object_name(Authentication)` | rename user as victim] | where signInTime >= clickTime AND signInTime <= clickTime + 3600 | eval delaySec = signInTime - clickTime | convert ctime(clickTime) ctime(signInTime)
```

**Defender KQL:**
```kql
let WindowMin = 60m;
let Clicks = UrlClickEvents
    | where Timestamp > ago(7d)
    | where Url has_any ("meet.google.com/linkredirect","adservice.google.com.ph","adservice.google.com","google.com/url","workers.dev","vazquezfleytas","edificiocristal","velvorra","furqanmustafa","unitedtechnofzmlogies","rydezyhrsysteminc","spectrhwqumbrands","rtzcoekdrporation","reliabilityinoperations","staiwooje.app","link-form-unj9.p-sm7rw6ru.workers.dev","data-cloud-ofe8.p-8yejy42o.workers.dev")
    | where ActionType in ("ClickAllowed","ClickedThrough")
    | project ClickTime = Timestamp, AccountUpn, ClickedUrl = Url, NetworkMessageId, IPAddress;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where AuthenticationProcessingDetails has "Device Code" or AuthenticationDetails has "deviceCode"
| where ErrorCode == 0
| join kind=inner Clicks on $left.AccountUpn == $right.AccountUpn
| where Timestamp between (ClickTime .. ClickTime + WindowMin)
| extend DelaySec = datetime_diff('second', Timestamp, ClickTime)
| project ClickTime, SignInTime = Timestamp, DelaySec, AccountUpn, ClickedUrl, NetworkMessageId, ClickIP = IPAddress1, SignInIP = IPAddress, Country, City, Application, ApplicationId, UserAgent
| order by ClickTime desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `vazquezfleytas.com`, `edificiocristal.pt`, `velvorra.com`, `furqanmustafa.com`, `unitedtechnofzmlogies.vu`, `cloudbemismanufacturingcompanygroup.rydezyhrsysteminc.vu`, `servicetriumphgroupsimplyappraisals.spectrhwqumbrands.vu`, `cloudgillettebrandberkshirehathaway.rtzcoekdrporation.vu` _(+4 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
