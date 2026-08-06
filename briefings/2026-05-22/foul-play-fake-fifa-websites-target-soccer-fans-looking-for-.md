# [MED] Foul play: Fake FIFA websites target soccer fans looking for World Cup tickets, merchandise

**Source:** ESET WeLiveSecurity
**Published:** 2026-05-22
**Article:** https://www.welivesecurity.com/en/cybersecurity/foul-play-fake-fifa-world-cup-websites-tickets/

## Threat Profile

As the FIFA World Cup 2026™ in the United States, Canada, and Mexico draws closer, anticipation is building toward fever pitch. Many soccer fans may still be hunting for tickets, merchandise, travel and hospitality packages – and scammers know exactly how to exploit this demand. In other words, many people are already in the state of mind that scammers count on: interested, impatient and, indeed, maybe a little worried that the tickets or other goods will sell out. Which is ultimately what makes…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `fifa26.shop`
- **Domain (defanged):** `fifaworldcup26.hospitality.fifa.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1566.003** — Phishing: Spearphishing via Service
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Mail-borne click to fake FIFA World Cup 2026 phishing domain

`UC_426_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.http_referrer) as referrer values(Web.url) as url from datamodel=Web where (Web.url="*fifa26.shop*" OR Web.url="*26-fifa.*" OR Web.url="*fifa*worldcup*" Web.url IN ("*.shop/*","*.store/*","*.online/*","*.xyz/*","*.top/*")) AND NOT (Web.url="*fifa.com/*" OR Web.url="*fifa.com.*") by Web.src Web.user Web.dest Web.url Web.http_referrer | `drop_dm_object_name("Web")` | where match(referrer, "(?i)(mail|outlook|gmail|owa|webmail|m365)") OR isnull(referrer) | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let TyposquatRegex = @'(?i)(fifa.*(26|2026|worldcup)|(26|2026|worldcup).*fifa)';
let KnownBad = dynamic(['fifa26.shop','26-fifa.com']);
let ClickedUrls = UrlClickEvents
  | where Timestamp > ago(7d)
  | where ActionType in ('ClickAllowed','ClickedThrough','UrlScanInProgress')
  | where Url matches regex TyposquatRegex or parse_url(Url).Host has_any (KnownBad)
  | where not (Url matches regex @'(?i)://(www\.)?fifa\.com(/|$)');
ClickedUrls
| join kind=leftouter (EmailUrlInfo | where Timestamp > ago(7d) | project NetworkMessageId, UrlDomain, MailUrl=Url) on NetworkMessageId
| project Timestamp, AccountUpn, Url, MailUrl, UrlDomain, ActionType, ThreatTypes, NetworkMessageId, IPAddress, IsClickedThrough
| order by Timestamp desc
```

### Endpoint DNS or web traffic to fake FIFA World Cup 2026 typosquat domain

`UC_426_5` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.answer) as answer from datamodel=Network_Resolution where (DNS.query="fifa26.shop" OR DNS.query="*.fifa26.shop" OR DNS.query="*26-fifa.com" OR DNS.query="*26-fifa.*" OR DNS.query="*26fifa.shop" OR DNS.query="*fifa*worldcup*.shop" OR DNS.query="*fifa*worldcup*.store") AND NOT (DNS.query="*.fifa.com" OR DNS.query="fifa.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name("DNS")` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let TyposquatRegex = @'(?i)(fifa.*(26|2026|worldcup)|(26|2026|worldcup).*fifa)\.(shop|store|online|xyz|top|site|com)';
let KnownBad = dynamic(['fifa26.shop','26-fifa.com']);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| extend Host = tolower(tostring(parse_url(RemoteUrl).Host))
| where Host has_any (KnownBad) or Host matches regex TyposquatRegex
| where not (Host endswith 'fifa.com') and Host != 'fifa.com'
| where InitiatingProcessFileName in~ ('chrome.exe','msedge.exe','firefox.exe','brave.exe','opera.exe','iexplore.exe','safari.exe')
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, RemoteUrl, Host, RemoteIP, RemotePort, InitiatingProcessCommandLine
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `fifa26.shop`, `fifaworldcup26.hospitality.fifa.com`


## Why this matters

Severity classified as **MED** based on: IOCs present, 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
