# [CRIT] New Bluekit phishing service includes an AI assistant, 40 templates

**Source:** BleepingComputer
**Published:** 2026-04-30
**Article:** https://www.bleepingcomputer.com/news/security/new-bluekit-phishing-service-includes-an-ai-assistant-40-templates/

## Threat Profile

New Bluekit phishing service includes an AI assistant, 40 templates 
By Bill Toulas 
April 30, 2026
02:58 PM
0 
A new phishing kit named Bluekit offers more than 40 templates targeting popular services and includes basic AI features for generating campaign drafts.
Available templates can be used to target email accounts (Outlook, Hotmail, Gmail, Yahoo, ProtonMail), cloud services (iCloud), developer platforms (GitHub), and cryptocurrency services (Ledger).
What makes the kit stand out is the pre…

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
- **T1583.001** — Acquire Infrastructure: Domains
- **T1567** — Exfiltration Over Web Service
- **T1566.002** — Phishing: Spearphishing Link
- **T1557** — Adversary-in-the-Middle
- **T1539** — Steal Web Session Cookie

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Endpoint traffic to known Bluekit PhaaS operator/panel infrastructure (bluekit.pk/.su/.cc)

`UC_1_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.http_user_agent) as ua from datamodel=Web.Web where (Web.dest IN ("bluekit.pk","bluekit.su","bluekit.cc") OR Web.url="*bluekit.pk*" OR Web.url="*bluekit.su*" OR Web.url="*bluekit.cc*") by Web.src Web.user Web.dest | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats summariesonly=true count from datamodel=Network_Resolution.DNS where DNS.query IN ("bluekit.pk","*.bluekit.pk","bluekit.su","*.bluekit.su","bluekit.cc","*.bluekit.cc") by DNS.src DNS.query | `drop_dm_object_name(DNS)` ]
```

**Defender KQL:**
```kql
let bluekit_hosts = dynamic(["bluekit.pk","bluekit.su","bluekit.cc"]);
union
( DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has_any (bluekit_hosts) or tolower(RemoteUrl) matches regex @"(^|//|\.)bluekit\.(pk|su|cc)(/|:|$)"
  | project Timestamp, DeviceName, ActionType, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName=InitiatingProcessAccountName
),
( DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "DnsQueryResponse" or ActionType startswith "Dns"
  | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
  | where QueryName has_any (bluekit_hosts)
  | project Timestamp, DeviceName, ActionType, QueryName, InitiatingProcessFileName, AccountName=InitiatingProcessAccountName
)
```

### [LLM] Lookalike-domain visits impersonating Bluekit's distinctive brand template set (Ledger/ProtonMail/Zoho/Zara)

`UC_1_5` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls from datamodel=Web.Web where Web.dest!="" by Web.src Web.user Web.dest | `drop_dm_object_name(Web)` | eval dest_lc=lower(dest) | where match(dest_lc,"(^|[.-])(ledger|protonmail|proton-mail|zoho|zara|icloud|appleid|apple-id|github|gmail|outlook|hotmail|yahoo|twitter)([.-]|$)") | where NOT match(dest_lc,"(^|\.)(ledger\.com|ledger\.fr|proton\.me|protonmail\.com|zoho\.com|zoho\.eu|zara\.com|inditex\.com|icloud\.com|apple\.com|github\.com|githubusercontent\.com|gmail\.com|google\.com|googleusercontent\.com|outlook\.com|live\.com|office\.com|microsoft\.com|hotmail\.com|yahoo\.com|twitter\.com|x\.com)$") | where NOT match(dest_lc,"(akamai|cloudfront|cloudflare|fastly|azureedge|edgekey)") | join type=left dest [ | tstats summariesonly=true min(_time) as domain_first_seen from datamodel=Web.Web by Web.dest | `drop_dm_object_name(Web)` ] | eval age_days=round((firstTime-domain_first_seen)/86400,1) | where domain_first_seen >= relative_time(now(),"-14d") | table firstTime lastTime src user dest age_days count urls | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let brand_regex = @"(^|[.\-])(ledger|protonmail|proton-mail|zoho|zara|icloud|appleid|apple-id|github|gmail|outlook|hotmail|yahoo|twitter)([.\-]|$)";
let legit_suffixes = dynamic(["ledger.com","ledger.fr","proton.me","protonmail.com","zoho.com","zoho.eu","zara.com","inditex.com","icloud.com","apple.com","github.com","githubusercontent.com","gmail.com","google.com","googleusercontent.com","outlook.com","live.com","office.com","microsoft.com","hotmail.com","yahoo.com","twitter.com","x.com"]);
let cdn_tokens = dynamic(["akamai","cloudfront","cloudflare","fastly","azureedge","edgekey"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where isnotempty(RemoteUrl)
| extend host = tolower(tostring(parse_url(RemoteUrl).Host))
| where host matches regex brand_regex
| where not(host has_any (legit_suffixes))
| where not(host has_any (cdn_tokens))
| summarize first_seen=min(Timestamp), last_seen=max(Timestamp), hits=count(), users=make_set(InitiatingProcessAccountName,5), procs=make_set(InitiatingProcessFileName,5) by DeviceName, host
| where first_seen > ago(14d)  // emphasise newly-seen lookalikes
| order by first_seen asc
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
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: 6 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
