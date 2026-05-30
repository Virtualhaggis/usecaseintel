# [HIGH] Charter Communications data breach affects 4.9 million accounts

**Source:** BleepingComputer
**Published:** 2026-05-29
**Article:** https://www.bleepingcomputer.com/news/security/charter-communications-data-breach-affects-49-million-accounts/

## Threat Profile

Charter Communications data breach affects 4.9 million accounts 
By Sergiu Gatlan 
May 29, 2026
04:29 AM
0 
The ShinyHunters extortion gang stole personal information from 4.9 million accounts after hacking the U.S. telecom giant Charter Communications in early April, according to data breach notification service Have I Been Pwned.
Charter has over 92,000 employees and provides internet, mobile, video, and voice services to more than 32 million customers and over 57 million homes in 41 states ac…

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
- **T1566.004** — Phishing: Spearphishing Voice
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1528** — Steal Application Access Token
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1530** — Data from Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090.003** — Proxy: Multi-hop Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vishing-induced Entra ID sign-in from new location/IP after employee call

`UC_40_3` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action=success Authentication.signature_id="AAD-Interactive" by Authentication.user Authentication.src Authentication.src_country Authentication.app | `drop_dm_object_name(Authentication)` | eval recent=if(firstTime>=relative_time(now(),"-7d"),1,0) | where recent=1 | join type=left user [| tstats summariesonly=true dc(src_country) as historic_countries min(_time) as historic_first from datamodel=Authentication where Authentication.action=success earliest=-90d@d latest=-7d@d by Authentication.user | `drop_dm_object_name(Authentication)`] | where isnull(historic_countries) OR historic_countries<=2 | table firstTime user src src_country app
```

**Defender KQL:**
```kql
let lookback = 30d;
let recent = 24h;
let KnownIPs = AADSignInEventsBeta
    | where Timestamp between (ago(lookback) .. ago(recent))
    | where ErrorCode == 0
    | summarize by AccountUpn, IPAddress;
let KnownCountries = AADSignInEventsBeta
    | where Timestamp between (ago(lookback) .. ago(recent))
    | where ErrorCode == 0
    | summarize by AccountUpn, Country;
AADSignInEventsBeta
| where Timestamp > ago(recent)
| where ErrorCode == 0
| where IsInteractive == true
| where isnotempty(AccountUpn)
| join kind=leftanti KnownIPs on AccountUpn, IPAddress
| join kind=leftanti KnownCountries on AccountUpn, Country
| extend AuthMethods = tostring(AuthenticationDetails)
| where AuthMethods has_any ("Mobile app notification","Phone call","Text","SMS")
| project Timestamp, AccountUpn, IPAddress, Country, City, UserAgent, ClientAppUsed, Application, RiskLevelDuringSignIn, ConditionalAccessStatus, AuthMethods
| order by Timestamp desc
```

### [LLM] OAuth consent granted to look-alike Salesforce/Data-Loader app from compromised employee

`UC_40_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Change where Change.action=created Change.object_category=oauth_app by Change.user Change.object Change.result _time | `drop_dm_object_name(Change)` | rex field=object "(?i)(?<lure>data\s?loader|salesforce|my\s?ticket\s?portal|salesforce\s?inc)" | where isnotnull(lure) | table _time user object result lure
```

**Defender KQL:**
```kql
let LureApps = dynamic(["Salesforce Inc. Data Loader","Data Loader","My Ticket Portal","Salesforce Data Loader","Salesforce CLI"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("Consent to application.","Add delegated permission grant.","Add OAuth2PermissionGrant.")
| extend AppName = tostring(parse_json(tostring(RawEventData)).ModifiedProperties[0].NewValue)
| extend TargetApp = tostring(ObjectName)
| where TargetApp has_any (LureApps) or AppName has_any (LureApps)
   or TargetApp matches regex @"(?i)(data\s?loader|salesforce.*data|my\s?ticket\s?portal)"
| extend Consenter = AccountDisplayName, ConsenterUpn = tostring(parse_json(tostring(RawEventData)).UserId)
| project Timestamp, Consenter, ConsenterUpn, TargetApp, AppName, IPAddress, UserAgent, CountryCode, IsAdminOperation, ActionType
| order by Timestamp desc
```

### [LLM] Salesforce Bulk/REST API mass-export volume burst from newly-consented app

`UC_40_5` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`salesforce_eventlogfile` EVENT_TYPE IN ("API","BulkApi","BulkApi2","RestApi") | stats sum(ROWS_PROCESSED) as records dc(ENTITY_NAME) as objects values(ENTITY_NAME) as objs by USER_ID CLIENT_NAME SOURCE_IP _time span=1h | where records > 50000 OR (objects>=2 AND records>10000) | where match(objs,"(?i)(Account|Contact|Lead|Case|User)")
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| where ActionType in ("BulkApiRequest","RestApiRequest","ApiCall","ApiTotalUsage","BulkApi2")
| extend Records = tolong(parse_json(tostring(RawEventData)).RowsProcessed)
| extend Object = tostring(parse_json(tostring(RawEventData)).EntityName)
| extend ClientName = tostring(parse_json(tostring(RawEventData)).ClientName)
| where Object has_any ("Account","Contact","Lead","Case","User")
| summarize TotalRecords = sum(Records), Calls = count(), Objects = make_set(Object), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by AccountObjectId, AccountDisplayName, ClientName, IPAddress, bin(Timestamp, 1h)
| where TotalRecords > 50000 or Calls > 1000
| order by TotalRecords desc
```

### [LLM] ShinyHunters leak-site Charter URI checked from corporate browsing

`UC_40_6` · phase: **c2** · confidence: **Low**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.url IN ("*shinyhunters*","*.onion*","*tor2web*","*onion.ws*","*onion.ly*") OR Web.dest IN ("*shinyhunters*") by Web.src Web.user Web.url Web.http_user_agent _time | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl matches regex @"(?i)(shinyhunters|\.onion(\.ws|\.ly|\.cab|\.to|\.pet)?|tor2web)"
   or RemoteUrl has_any ("onion.ws","onion.ly","tor2web.io","darkfailllnkf4vf","shinyhunters")
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
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


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
