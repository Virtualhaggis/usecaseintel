# [HIGH] FBI warns of fake FIFA websites running World Cup fraud schemes

**Source:** BleepingComputer
**Published:** 2026-05-28
**Article:** https://www.bleepingcomputer.com/news/security/fbi-warns-of-fake-fifa-websites-running-world-cup-fraud-schemes/

## Threat Profile

FBI warns of fake FIFA websites running World Cup fraud schemes 
By Bill Toulas 
May 28, 2026
03:08 PM
0 
The FBI is warning of fake websites impersonating FIFA ahead of the 2026 World Cup, to steal personal and financial information, sell fake tickets and hospitality packages, and push other fraud related to the event.
With the international soccer tournament set between June 11 and July 19 in the United States, Canada, and Mexico, threat actors prepared hundreds of phishing sites.
According th…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `148.178.18.23`
- **IPv4 (defanged):** `148.178.18.60`
- **IPv4 (defanged):** `154.86.0.33`
- **IPv4 (defanged):** `207.56.1.93`
- **IPv4 (defanged):** `66.112.212.25`
- **IPv4 (defanged):** `148.178.16.48`
- **IPv4 (defanged):** `148.178.16.5`
- **IPv4 (defanged):** `104.225.235.49`
- **IPv4 (defanged):** `89.208.250.38`
- **IPv4 (defanged):** `65.49.223.138`
- **IPv4 (defanged):** `148.178.22.16`
- **IPv4 (defanged):** `85.121.242.41`
- **IPv4 (defanged):** `216.189.149.193`
- **IPv4 (defanged):** `137.220.224.67`
- **IPv4 (defanged):** `43.98.183.110`
- **Domain (defanged):** `fiffa.com`
- **Domain (defanged):** `jobs-fifa.com`
- **Domain (defanged):** `fifa-hiring.com`
- **Domain (defanged):** `fifa.bio`
- **Domain (defanged):** `fifa.sale`
- **Domain (defanged):** `fifa.shopping`
- **Domain (defanged):** `fifa.show`
- **Domain (defanged):** `fifa.cafe`
- **Domain (defanged):** `fifa.market`
- **Domain (defanged):** `fifa.cash`
- **Domain (defanged):** `fifa-com.co`
- **Domain (defanged):** `fifa-com.shop`
- **Domain (defanged):** `fifa-com.xyz`
- **Domain (defanged):** `fifa-com.vip`
- **Domain (defanged):** `www-fifa.com`
- **Domain (defanged):** `www-fifaworldcup.com`
- **Domain (defanged):** `wc26-fifa.com`
- **Domain (defanged):** `fifa-26-worldcup.com`
- **Domain (defanged):** `fifaweb.com`
- **Domain (defanged):** `football-ticket.top`
- **Domain (defanged):** `football-ticket.shop`
- **Domain (defanged):** `football-tickets.top`
- **Domain (defanged):** `fifa-tickets.vip`
- **Domain (defanged):** `mm-fifa.top`
- **Domain (defanged):** `faithoutfit.uk`
- **Domain (defanged):** `defwear.uk`
- **Domain (defanged):** `savebigwear.com`
- **Domain (defanged):** `teamcollections.com`
- **Domain (defanged):** `fanzonewear.com`
- **Domain (defanged):** `malskitukpatch.com`
- **SHA1:** `3b8bb7631b39f455d31544b55ba97b49ab1888c1`
- **SHA1:** `84ecdca915f1af822ccc8a04479f5179104f353c`
- **SHA1:** `9bd164dd3f50d196c7dff4f6c1b0f1345ac96d9a`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1189** — Drive-by Compromise
- **T1583.001** — Acquire Infrastructure: Domains
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1583.003** — Acquire Infrastructure: Virtual Private Server
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556** — Modify Authentication Process
- **T1539** — Steal Web Session Cookie

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DNS/HTTP traffic to Ghost Stadium FIFA typosquat domains (2026 World Cup fraud)

`UC_8_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_referrer) as referrers from datamodel=Web where (Web.dest IN ("fiffa.com","jobs-fifa.com","fifa-hiring.com","filfa.org","wvvw-fifa.com","ww-fifa.com","fifa-hr.com","fifa-careerhub.com") OR Web.url="*fiffa.com*" OR Web.url="*jobs-fifa.com*" OR Web.url="*fifa-hiring.com*" OR Web.url="*filfa.org*" OR Web.url="*wvvw-fifa.com*" OR Web.url="*ww-fifa.com*" OR Web.url="*fifa-hr.com*" OR Web.url="*fifa-careerhub.com*") by Web.src, Web.user, Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let TyposquatDomains = dynamic(["fiffa.com","jobs-fifa.com","fifa-hiring.com","filfa.org","wvvw-fifa.com","ww-fifa.com","fifa-hr.com","fifa-careerhub.com"]);
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has_any (TyposquatDomains)
    | project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, InitiatingProcessFileName, RemoteUrl, RemoteIP, Source="DeviceNetworkEvents";
let ClickHits = UrlClickEvents
    | where Timestamp > ago(14d)
    | where Url has_any (TyposquatDomains)
    | project Timestamp, DeviceName="", AccountUpn, InitiatingProcessFileName="", RemoteUrl=Url, RemoteIP="", Source="UrlClickEvents";
union NetHits, ClickHits
| order by Timestamp desc
```

### [LLM] Outbound connection to Ghost Stadium FIFA fraud staging IPs

`UC_8_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_port) as ports values(All_Traffic.app) as apps from datamodel=Network_Traffic where All_Traffic.dest IN ("148.178.18.23","148.178.18.60","154.86.0.33","207.56.1.93","66.112.212.25","148.178.16.48","148.178.16.5","104.225.235.49") by All_Traffic.src, All_Traffic.user, All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let StagingIPs = dynamic(["148.178.18.23","148.178.18.60","154.86.0.33","207.56.1.93","66.112.212.25","148.178.16.48","148.178.16.5","104.225.235.49"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (StagingIPs)
| project Timestamp, DeviceName, AccountUpn=InitiatingProcessAccountUpn, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, Protocol
| order by Timestamp desc
```

### [LLM] Browser navigation to FIFA-themed look-alike hostname (typosquat pattern hunt)

`UC_8_7` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls from datamodel=Web where Web.dest="*fifa*" AND Web.dest!="fifa.com" AND Web.dest!="*.fifa.com" AND Web.dest!="fifa.org" AND Web.dest!="*.fifa.org" by Web.src, Web.user, Web.dest | `drop_dm_object_name(Web)` | regex dest="(?i)(fiff[ai]|filfa|f1fa|fifaa|wvvw-?fifa|ww-?fifa|fifa-?(hiring|hr|ticket|tickets|careers?|careerhub|jobs|hospitality|online|com|world(cup)?|2026|store|merch|panini))" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| where isnotempty(RemoteUrl)
| extend Hostname = tolower(tostring(parse_url(RemoteUrl)["Host"]))
| where Hostname matches regex @"(fiff[ai]|filfa|f1fa|fifaa|wvvw-?fifa|ww-?fifa|fifa-?(hiring|hr|ticket|tickets|careers?|careerhub|jobs|hospitality|online|com|worldcup|world-cup|2026|store|merch|panini))"
| where Hostname != "fifa.com" and Hostname != "fifa.org" and Hostname !endswith ".fifa.com" and Hostname !endswith ".fifa.org"
| summarize HitCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Devices=dcount(DeviceName), Users=dcount(InitiatingProcessAccountUpn), SampleUrls=make_set(RemoteUrl, 5) by Hostname
| order by FirstSeen desc
```

### [LLM] Risky AAD sign-in after user contact with FIFA typosquat phishing portal

`UC_8_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Web where (Web.dest IN ("fiffa.com","jobs-fifa.com","fifa-hiring.com","filfa.org","wvvw-fifa.com","ww-fifa.com","fifa-hr.com","fifa-careerhub.com")) by Web.user, _time | `drop_dm_object_name(Web)` | rename _time as visitTime user as visitor | join visitor [| tstats summariesonly=t count from datamodel=Authentication where (Authentication.action=success AND (Authentication.signature="risky" OR Authentication.signature="highRisk" OR Authentication.signature="mediumRisk")) by Authentication.user, Authentication.src, _time | `drop_dm_object_name(Authentication)` | rename user as visitor _time as signinTime] | where signinTime >= visitTime AND signinTime <= visitTime + 604800 | eval delaySec = signinTime - visitTime | table visitTime, signinTime, delaySec, visitor, src
```

**Defender KQL:**
```kql
let TyposquatDomains = dynamic(["fiffa.com","jobs-fifa.com","fifa-hiring.com","filfa.org","wvvw-fifa.com","ww-fifa.com","fifa-hr.com","fifa-careerhub.com"]);
let Visitors = union
    (DeviceNetworkEvents | where Timestamp > ago(14d) | where RemoteUrl has_any (TyposquatDomains) | where isnotempty(InitiatingProcessAccountUpn) | project VisitTime=Timestamp, AccountUpn=tolower(InitiatingProcessAccountUpn), DeviceName, VisitedHost=RemoteUrl),
    (UrlClickEvents | where Timestamp > ago(14d) | where Url has_any (TyposquatDomains) | where isnotempty(AccountUpn) | project VisitTime=Timestamp, AccountUpn=tolower(AccountUpn), DeviceName="", VisitedHost=Url);
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where ErrorCode == 0
| where RiskLevelDuringSignIn in ("medium","high") or RiskLevelAggregated in ("medium","high") or RiskState in ("atRisk","confirmedCompromised")
| extend AccountUpn=tolower(AccountUpn)
| join kind=inner Visitors on AccountUpn
| where Timestamp between (VisitTime .. VisitTime + 7d)
| extend DelayHours = datetime_diff('hour', Timestamp, VisitTime)
| project SignInTime=Timestamp, VisitTime, DelayHours, AccountUpn, IPAddress, Country, City, RiskLevelDuringSignIn, RiskState, Application, VisitedHost, DeviceName
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `148.178.18.23`, `148.178.18.60`, `154.86.0.33`, `207.56.1.93`, `66.112.212.25`, `148.178.16.48`, `148.178.16.5`, `104.225.235.49` _(+37 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `3b8bb7631b39f455d31544b55ba97b49ab1888c1`, `84ecdca915f1af822ccc8a04479f5179104f353c`, `9bd164dd3f50d196c7dff4f6c1b0f1345ac96d9a`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
