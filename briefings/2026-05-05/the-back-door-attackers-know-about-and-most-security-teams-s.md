# [CRIT] The Back Door Attackers Know About — and Most Security Teams Still Haven’t Closed

**Source:** The Hacker News
**Published:** 2026-05-05
**Article:** https://thehackernews.com/2026/05/the-back-door-attackers-know-about-and.html

## Threat Profile

The Back Door Attackers Know About — and Most Security Teams Still Haven’t Closed 
 The Hacker News  May 05, 2026 SaaS Security / Enterprise Security 
Every AI tool, workflow automation, and productivity app your employees connected to Google or Microsoft this year left something behind: a persistent OAuth token with no expiration date, no automatic cleanup, and in most organizations, no one watching it. Your perimeter controls don't see it. Your MFA doesn't stop it. And when an attacker gets …

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1199** — Trusted Relationship
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1213.002** — Data from Information Repositories: Sharepoint / SaaS
- **T1119** — Automated Collection
- **T1090.003** — Proxy: Multi-hop Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] UNC6395 user-agent strings on Salesforce / OAuth-integrated SaaS API access

`UC_177_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.src) as src values(Web.dest) as dest values(Web.user) as user values(Web.url) as url from datamodel=Web where (Web.http_user_agent="Salesforce-Multi-Org-Fetcher/1.0" OR Web.http_user_agent="python-requests/2.32.4" OR Web.http_user_agent="Python/3.11 aiohttp/3.12.15") by Web.http_user_agent Web.src Web.user | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// UNC6395 / Salesloft Drift OAuth abuse — known custom user-agent strings
// Reference: Unit 42, Google TIG (Aug 2025)
let _unc6395_uas = dynamic(["Salesforce-Multi-Org-Fetcher/1.0","python-requests/2.32.4","Python/3.11 aiohttp/3.12.15"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any ("Salesforce","Drift","Salesloft")
   or ApplicationId in ("11114")        // 11114 = Salesforce in MDA app catalog
| where UserAgent in~ (_unc6395_uas)
| project Timestamp, Application, AccountDisplayName, AccountObjectId,
          IPAddress, CountryCode, ISP, IsAnonymousProxy, UserAgent,
          ActionType, ActivityType, ObjectName, ObjectType
| order by Timestamp desc
```

### [LLM] SOQL queries scanning Salesforce data for AWS / Snowflake / password credential strings

`UC_177_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`salesforce_eventlog` (EVENT_TYPE=UniqueQuery OR EVENT_TYPE=BulkApi OR EVENT_TYPE=BulkApi2 OR EVENT_TYPE=ReportExport)
| eval QueryLC=lower(QUERY)
| search QueryLC IN ("*akia*","*snowflakecomputing*","*aws_access_key*","*aws_secret*","*password*","*client_secret*","*api_key*","*xoxb-*","*xoxp-*")
| stats count min(_time) as firstTime max(_time) as lastTime values(QUERY) as queries values(USER_ID) as user values(CLIENT_IP) as src values(USER_AGENT) as ua by USER_ID CLIENT_NAME
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// Hunts SOQL / Bulk API queries against Salesforce that look for embedded credentials.
// CloudAppEvents.RawEventData carries the SOQL text for Defender for Cloud Apps
// when Salesforce Shield Event Monitoring is connected to MDA.
let _cred_keywords = dynamic(["AKIA","aws_access_key","aws_secret","snowflakecomputing","snowflake.com","password","client_secret","api_key","xoxb-","xoxp-","ghp_"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application =~ "Salesforce"
| where ActionType has_any ("UniqueQuery","BulkApi","BulkApi2","ReportExport","RestApi","ApiAnomaly")
| extend QueryText = tostring(parse_json(tostring(RawEventData)).QUERY)
| extend QueryLower = tolower(QueryText)
| where isnotempty(QueryText)
| where QueryLower has_any (_cred_keywords)
   or QueryLower matches regex @"\bakia[0-9a-z]{16}\b"
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode,
          UserAgent, ActionType, QueryText, ObjectName, ObjectType, RawEventData
| order by Timestamp desc
```

### [LLM] OAuth-integrated SaaS API access from Tor exit node / anonymous proxy

`UC_177_8` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Authentication.user) as user values(Authentication.app) as app values(Authentication.src) as src from datamodel=Authentication where Authentication.action=success Authentication.app IN ("salesforce","google_workspace","office365","slack","github") by Authentication.src Authentication.user Authentication.app
| `drop_dm_object_name(Authentication)`
| lookup tor_exit_nodes ip AS src OUTPUT is_tor
| where is_tor="true"
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// OAuth-mediated SaaS access from anonymous proxy / Tor — direct replay of stolen refresh token
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Salesforce","Google Workspace","Microsoft 365","Slack","GitHub","Drift","Salesloft")
| where IsAnonymousProxy == true
   or IPTags has_any ("Tor","Anonymous proxy","Hosting provider")
| summarize EventCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            Activities = make_set(ActivityType, 50),
            Objects = make_set(ObjectName, 50),
            SampleUA = any(UserAgent)
            by AccountDisplayName, AccountObjectId, Application, IPAddress, CountryCode, ISP
| order by FirstSeen desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
