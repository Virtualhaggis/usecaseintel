# [HIGH] INTERPOL Operation Takes Down Sniper Dz Phishing Platform, Arrests Administrator

**Source:** The Hacker News
**Published:** 2026-06-12
**Article:** https://thehackernews.com/2026/06/interpol-takes-down-sniper-dz-phishing.html

## Threat Profile

INTERPOL Operation Takes Down Sniper Dz Phishing Platform, Arrests Administrator 
 Ravie Lakshmanan  Jun 12, 2026 Cybercrime / Phishing 
An INTERPOL-led operation last month resulted in the disruption of Sniper Dz , a decade-long phishing-as-a-service (PhaaS) platform, Group-IB said Thursday.
The effort, codenamed Operation Ramz , took place between October 2025 and February 2026, and saw authorities from 13 countries in the Middle East and North Africa (MENA) region making 201 arrests.
Includ…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `sniperdz.com`
- **Domain (defanged):** `raviral.com`
- **Domain (defanged):** `t.me/JokerDzV2`
- **Domain (defanged):** `dev-cdn370.pantheonsite.io`
- **Domain (defanged):** `facebookbusiness0078.blogspot.be`
- **Domain (defanged):** `instagram-cutequeen57.netlify.app`
- **Domain (defanged):** `v0tingsystem.github.io`
- **Domain (defanged):** `freefirefff.github.io`
- **Domain (defanged):** `ff-rewards-redeem-codes-org.github.io`
- **Domain (defanged):** `automaticgiveaway.000webhostapp.com`
- **Domain (defanged):** `climbing-green-botany.glitch.me`
- **Domain (defanged):** `free-fire-reward-garena-bd-nepazl.epizy.com`
- **Domain (defanged):** `pubg-tournament-official.github.io`
- **Domain (defanged):** `pro.riccardomalisano.com`
- **Domain (defanged):** `raviral.com/k_fac.php`
- **Domain (defanged):** `raviral.com/host_style/style/js-track/track.js`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
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
- **T1568** — Dynamic Resolution
- **T1056.003** — Web Portal Capture
- **T1204.001** — Malicious Link
- **T1583.001** — Acquire Infrastructure: Domains

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Sniper Dz seized phishing infrastructure callback (post-takedown beacons)

`UC_32_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstSeen, max(_time) as lastSeen, values(DNS.src) as src_hosts from datamodel=Network_Resolution.DNS where DNS.query IN ("sniperdz.com","*.sniperdz.com","raviral.com","*.raviral.com","dev-cdn370.pantheonsite.io","facebookbusiness0078.blogspot.be","instagram-cutequeen57.netlify.app","v0tingsystem.github.io","freefirefff.github.io","ff-rewards-redeem-codes-org.github.io","automaticgiveaway.000webhostapp.com","climbing-green-botany.glitch.me","free-fire-reward-garena-bd-nepazl.epizy.com","pubg-tournament-official.github.io","pro.riccardomalisano.com") by DNS.query, DNS.src, host | `drop_dm_object_name(DNS)` | eval campaign="SniperDz_OperationRamz" | sort - lastSeen
```

**Defender KQL:**
```kql
let SniperDzInfra = dynamic(["sniperdz.com","raviral.com","dev-cdn370.pantheonsite.io","facebookbusiness0078.blogspot.be","instagram-cutequeen57.netlify.app","v0tingsystem.github.io","freefirefff.github.io","ff-rewards-redeem-codes-org.github.io","automaticgiveaway.000webhostapp.com","climbing-green-botany.glitch.me","free-fire-reward-garena-bd-nepazl.epizy.com","pubg-tournament-official.github.io","pro.riccardomalisano.com"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (SniperDzInfra)
| project Timestamp, DeviceName, DeviceId,
          AccountName = InitiatingProcessAccountName,
          RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Raviral.com Sniper Dz kit endpoints accessed (k_fac.php / track.js)

`UC_32_9` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Web.user) as users, values(Web.src) as src_hosts, max(_time) as lastSeen from datamodel=Web.Web where (Web.url="*/k_fac.php*" OR Web.url="*/host_style/style/js-track/track.js*" OR Web.dest="raviral.com" OR Web.dest="*.raviral.com") by Web.url, Web.dest, Web.http_method, Web.http_user_agent | `drop_dm_object_name(Web)` | eval campaign="SniperDz_kit_fingerprint" | sort - lastSeen
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any ("/k_fac.php", "/host_style/style/js-track/track.js")
   or RemoteUrl has "raviral.com"
| project Timestamp, DeviceName, DeviceId,
          AccountName = InitiatingProcessAccountName,
          RemoteUrl, RemoteIP,
          Browser = InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### Phishing email click landing on Sniper Dz infrastructure (URL/click correlation)

`UC_32_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(All_Email.recipient) as recipients, values(All_Email.subject) as subjects from datamodel=Email.All_Email where (All_Email.url="*sniperdz.com*" OR All_Email.url="*raviral.com*" OR All_Email.url="*dev-cdn370.pantheonsite.io*" OR All_Email.url="*facebookbusiness0078.blogspot.be*" OR All_Email.url="*instagram-cutequeen57.netlify.app*" OR All_Email.url="*v0tingsystem.github.io*" OR All_Email.url="*freefirefff.github.io*" OR All_Email.url="*ff-rewards-redeem-codes-org.github.io*" OR All_Email.url="*automaticgiveaway.000webhostapp.com*" OR All_Email.url="*climbing-green-botany.glitch.me*" OR All_Email.url="*free-fire-reward-garena-bd-nepazl.epizy.com*" OR All_Email.url="*pubg-tournament-official.github.io*" OR All_Email.url="*pro.riccardomalisano.com*") by All_Email.src_user, All_Email.recipient, All_Email.message_id, All_Email.url | `drop_dm_object_name(All_Email)` | eval campaign="SniperDz_OperationRamz" | sort - count
```

**Defender KQL:**
```kql
let SniperDzInfra = dynamic(["sniperdz.com","raviral.com","dev-cdn370.pantheonsite.io","facebookbusiness0078.blogspot.be","instagram-cutequeen57.netlify.app","v0tingsystem.github.io","freefirefff.github.io","ff-rewards-redeem-codes-org.github.io","automaticgiveaway.000webhostapp.com","climbing-green-botany.glitch.me","free-fire-reward-garena-bd-nepazl.epizy.com","pubg-tournament-official.github.io","pro.riccardomalisano.com"]);
let PhishingMail = EmailEvents
    | where Timestamp > ago(30d)
    | where EmailDirection == "Inbound"
    | join kind=inner (
        EmailUrlInfo
        | where Url has_any (SniperDzInfra) or UrlDomain has_any (SniperDzInfra)
      ) on NetworkMessageId
    | project NetworkMessageId, EmailTime=Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, Url, UrlDomain;
UrlClickEvents
| where Timestamp > ago(30d)
| where ActionType in ("ClickAllowed","ClickedThrough")
| where Url has_any (SniperDzInfra)
| join kind=leftouter PhishingMail on $left.NetworkMessageId == $right.NetworkMessageId
| project ClickTime=Timestamp, AccountUpn, IPAddress, ClickedUrl=Url, ActionType, IsClickedThrough,
          EmailTime, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation
| order by ClickTime desc
```

### Brand-impersonating phishing pages on abused free-hosting platforms (Sniper Dz pattern)

`UC_32_11` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstSeen, dc(Web.src) as host_count from datamodel=Web.Web where (Web.dest="*.github.io" OR Web.dest="*.netlify.app" OR Web.dest="*.glitch.me" OR Web.dest="*.pantheonsite.io" OR Web.dest="*.000webhostapp.com" OR Web.dest="*.epizy.com" OR Web.dest="*.blogspot.com" OR Web.dest="*.blogspot.be" OR Web.dest="*.web.app" OR Web.dest="*.herokuapp.com") by Web.dest, Web.url | `drop_dm_object_name(Web)` | where match(dest,"(?i)(paypal|facebook|fbpage|instagram|netflix|steam|yahoo|freefire|free-fire|garena|pubg|whatsapp|tiktok|gov|bank|signin|login|secure|verify|reward|giveaway|prize)") | eval pattern="SniperDz_freeHost_brandImpersonation" | sort - firstSeen
```

**Defender KQL:**
```kql
let BrandKeywords = dynamic(["paypal","facebook","fbpage","instagram","netflix","steam","yahoo","freefire","free-fire","garena","pubg","whatsapp","tiktok","signin","login","secure","verify","reward","giveaway","prize","redeem","voting","v0ting"]);
let FreeHostingTLDs = dynamic([".github.io",".netlify.app",".glitch.me",".pantheonsite.io",".000webhostapp.com",".epizy.com",".blogspot.com",".blogspot.be",".web.app",".herokuapp.com",".pages.dev",".vercel.app",".workers.dev"]);
let Baseline = DeviceNetworkEvents
    | where Timestamp between (ago(60d) .. ago(2d))
    | where isnotempty(RemoteUrl)
    | where RemoteUrl has_any (FreeHostingTLDs)
    | summarize by RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(2d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (FreeHostingTLDs)
| where RemoteUrl has_any (BrandKeywords)
| join kind=leftanti Baseline on RemoteUrl
| summarize FirstSeen = min(Timestamp), HostCount = dcount(DeviceName), AnyAccount = any(InitiatingProcessAccountName), AnyBrowser = any(InitiatingProcessFileName) by RemoteUrl
| where HostCount >= 1
| order by FirstSeen desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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
  - IP / domain IOC(s): `sniperdz.com`, `raviral.com`, `t.me/JokerDzV2`, `dev-cdn370.pantheonsite.io`, `facebookbusiness0078.blogspot.be`, `instagram-cutequeen57.netlify.app`, `v0tingsystem.github.io`, `freefirefff.github.io` _(+8 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
