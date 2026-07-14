# [CRIT] Microsoft Maps Three Salesforce Attack Paths Tied to a Year of ShinyHunters Activity

**Source:** The Hacker News
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/microsoft-maps-year-long-shinyhunters.html

## Threat Profile

Microsoft Maps Three Salesforce Attack Paths Tied to a Year of ShinyHunters Activity 
 Swati Khandelwal  Jul 14, 2026 SaaS Security / Identity Security 
Attackers whose methods line up with the data-extortion group ShinyHunters have spent the past year walking into corporate Salesforce environments without exploiting a single flaw in the platform.
The way in has been the trust the organization had already extended, usually through the OAuth connections that tie Salesforce to the apps and third…

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1566.004** — Phishing: Spearphishing Voice
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1530** — Data from Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1213** — Data from Information Repositories
- **T1070** — Indicator Removal
- **T1070.004** — Indicator Removal: File Deletion
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Salesforce consent to spoofed 'Data Loader' connected app (UNC6040 vishing)

`UC_22_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=sfdc:* (EVENT_TYPE="ConnectedApp*" OR ACTION="consent" OR "OAuth" OR "connected app") 
| search APP_NAME="*Data Loader*" OR CONNECTED_APP_NAME="*Data Loader*" OR OBJECT_NAME="*Data Loader*" 
| stats count min(_time) as firstTime max(_time) as lastTime values(SOURCE_IP) as src values(COUNTRY) as country by USER_NAME, APP_NAME, EVENT_TYPE 
| convert ctime(firstTime) ctime(lastTime) 
| sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Salesforce"
| where ActionType has_any ("Consent","Connected","OAuth","Authorize","Grant")
| extend Raw = parse_json(RawEventData)
| extend ConsentedApp = coalesce(tostring(Raw.ConnectedApplication), tostring(Raw.ConnectedAppName), ObjectName)
| where ConsentedApp has "Data Loader"
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ISP, UserAgent, ActionType, ConsentedApp, ObjectId
| order by Timestamp desc
```

### Compromised vendor OAuth integration (Drift/Gainsight/Klue) mass Salesforce export

`UC_22_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=sfdc:* (EVENT_TYPE="ApiEvent" OR EVENT_TYPE="BulkApiResultEvent" OR EVENT_TYPE="ReportExportEvent") 
| search CONNECTED_APP_NAME IN ("*Drift*","*Gainsight*","*Klue*") OR APP_NAME IN ("*Drift*","*Gainsight*","*Klue*") 
| eval rows=coalesce(ROWS_PROCESSED,NUMBER_OF_RECORDS,ROW_COUNT,0) 
| stats sum(rows) as totalRows count as queries dc(SOURCE_IP) as srcIPs values(SOURCE_IP) as src min(_time) as firstTime max(_time) as lastTime by CONNECTED_APP_NAME, USER_NAME 
| where totalRows > 50000 OR queries > 500 
| convert ctime(firstTime) ctime(lastTime) 
| sort - totalRows
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Salesforce"
| where ActionType has_any ("Api","Bulk","Report","Export","Query")
| extend Raw = parse_json(RawEventData)
| extend AppName = coalesce(tostring(Raw.ConnectedApplication), tostring(Raw.ClientName))
| where AppName has_any ("Drift","Gainsight","Klue")
| extend Rows = toint(coalesce(Raw.RowsProcessed, Raw.NumberOfRecords, Raw.RowCount))
| summarize TotalRows = sum(Rows), Queries = count(), SrcIps = make_set(IPAddress, 15), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AppName, AccountDisplayName
| where TotalRows > 50000 or Queries > 500   // 50k rows / 500 calls = well above a normal chat/CI integration sync cadence
| order by TotalRows desc
```

### Salesforce SOQL secret-hunting across Case/support objects (AWS/Snowflake/VPN)

`UC_22_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=sfdc:* EVENT_TYPE="ApiEvent" 
| eval soql=coalesce(QUERY,SOQL,QUERY_STRING) 
| search soql IN ("*AKIA*","*aws_secret*","*aws_access*","*snowflakecomputing*","*snowflake*","*password*","*passwd*","*private_key*","*apikey*","*vpn*") 
| stats count min(_time) as firstTime max(_time) as lastTime values(SOURCE_IP) as src values(soql) as queries by USER_NAME, CONNECTED_APP_NAME 
| convert ctime(firstTime) ctime(lastTime) 
| sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Salesforce"
| where ActionType has_any ("Api","Query","Report","Bulk")
| extend Raw = parse_json(RawEventData)
| extend Soql = tostring(coalesce(Raw.Query, Raw.QueryString, Raw.Soql))
| where Soql has_any ("AKIA","aws_secret","aws_access","snowflakecomputing","snowflake","vpn","password","passwd","private_key","apikey","api_key","secret")
| project Timestamp, AccountDisplayName, IPAddress, CountryCode, ISP, ActionType, Soql
| order by Timestamp desc
```

### Anti-forensic deletion of Salesforce async query/bulk job records

`UC_22_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=sfdc:* (ACTION="delete" OR ACTION="abort" OR EVENT_TYPE="BulkApiJobAbort" OR OPERATION="delete") 
| search OBJECT_TYPE IN ("AsyncApexJob","BackgroundOperation","BulkApiJob") OR ENTITY_NAME IN ("AsyncApexJob","BackgroundOperation") 
| stats count min(_time) as firstTime max(_time) as lastTime values(SOURCE_IP) as src values(OBJECT_ID) as jobs by USER_NAME, CONNECTED_APP_NAME, ACTION 
| convert ctime(firstTime) ctime(lastTime) 
| sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Salesforce"
| where ActionType has_any ("Delete","Abort","Remove")
| extend Raw = parse_json(RawEventData)
| extend TargetObj = coalesce(ObjectType, tostring(Raw.EntityName), tostring(Raw.ObjectType))
| where TargetObj has_any ("AsyncApexJob","BackgroundOperation","BulkApiJob","BulkApi") or ActionType has "Abort"
| project Timestamp, AccountDisplayName, IPAddress, CountryCode, ActionType, ObjectType, ObjectName, ObjectId
| order by Timestamp desc
```

### Unauthenticated Salesforce Aura/GraphQL guest scraping past 2,000-record limit

`UC_22_9` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.http_user_agent) as user_agents values(Web.uri_path) as paths from datamodel=Web where (Web.url="*/s/sfsites/aura*" OR Web.uri_path="*/s/sfsites/aura*") by Web.src, Web.dest, _time span=1h 
| `drop_dm_object_name(Web)` 
| where count > 200 
| sort - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Salesforce"
| extend Raw = parse_json(RawEventData)
| extend Uri = tostring(coalesce(Raw.Uri, Raw.RequestUrl, Raw.Page))
| where Uri has "/s/sfsites/aura" or Uri has "aura?r="
| where AccountType has_any ("Guest","Anonymous","Unauthenticated") or UserAgent has "AuraInspector"
| summarize Requests = count(), Uris = dcount(Uri), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by IPAddress, UserAgent, CountryCode, ISP
| where Requests > 200   // cursor-paginated scraping (2000-row pages) far exceeds human browsing of a public site
| order by Requests desc
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


## Why this matters

Severity classified as **CRIT** based on: 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
