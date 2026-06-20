# [HIGH] Klue OAuth breach victim list grows as Icarus hackers claim attack

**Source:** BleepingComputer
**Published:** 2026-06-19
**Article:** https://www.bleepingcomputer.com/news/security/klue-oauth-breach-victim-list-grows-as-icarus-hackers-claim-attack/

## Threat Profile

Klue OAuth breach victim list grows as Icarus hackers claim attack 
By Lawrence Abrams 
June 19, 2026
06:31 PM
0 
Market intelligence platform Klue has publicly confirmed a recent security incident that allowed threat actors to steal OAuth tokens used to connect to customers' Salesforce environments, as the new "Icarus" extortion group publicly claims the attack.
The disclosure comes after cybersecurity firms Huntress and ReliaQuest detailed how attackers abused compromised Klue Battlecards inte…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `138.226.246.94`
- **IPv4 (defanged):** `212.86.125.24`
- **IPv4 (defanged):** `213.111.148.90`
- **IPv4 (defanged):** `94.154.32.160`
- **Domain (defanged):** `klue.com`

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
- **T1071** — Application Layer Protocol
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1199** — Trusted Relationship
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1119** — Automated Collection
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1657** — Financial Theft
- **T1071.003** — Application Layer Protocol: Mail Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Auth from Icarus Klue-breach operator IPs (138.226.246.94 / 212.86.125.24 / 213.111.148.90 / 94.154.32.160)

`UC_3_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.app) as app values(Authentication.action) as action values(Authentication.user_agent) as user_agent from datamodel=Authentication where Authentication.src in ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") by Authentication.user Authentication.src Authentication.dest | `drop_dm_object_name("Authentication")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where IPAddress in (IcarusIPs)
| project Timestamp, AccountUpn, AccountDisplayName, Application, ApplicationId, ResourceDisplayName, IPAddress, Country, UserAgent, ClientAppUsed, ErrorCode, ConditionalAccessStatus, IsInteractive, TokenIssuerType
| order by Timestamp desc
```

### Klue Battlecards Salesforce connected-app activity from non-Klue source IPs

`UC_3_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.user_agent) as ua values(Authentication.action) as action from datamodel=Authentication where Authentication.app="salesforce" AND (Authentication.signature_id IN ("Klue","Klue Battlecards") OR Authentication.dest_user_agent IN ("Klue","Klue Battlecards")) by Authentication.user Authentication.src Authentication.dest | `drop_dm_object_name("Authentication")` | search src IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") OR NOT cidrmatch("34.192.0.0/12", src) | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "Salesforce"
| where IPAddress in (IcarusIPs)
   or (tostring(RawEventData) has_any ("Klue Battlecards","Klue") and AccountDisplayName has_any ("klue","battlecards"))
| project Timestamp, AccountDisplayName, AccountObjectId, Application, ActionType, ActivityType, ObjectName, ObjectType, IPAddress, CountryCode, ISP, UserAgent, IsAdminOperation, RawEventData
| order by Timestamp desc
```

### Python automation user-agent (python-requests / simple-salesforce) hitting Salesforce API at scale

`UC_3_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.url="*my.salesforce.com*" OR Web.url="*.force.com*" OR Web.dest_category="salesforce" by Web.src Web.user Web.http_user_agent _time span=1h | `drop_dm_object_name("Web")` | search http_user_agent IN ("python-requests*","*simple-salesforce*","*python-urllib*","Python/*","*aiohttp*") | stats sum(count) as api_calls dc(http_user_agent) as ua_variants values(http_user_agent) as user_agents min(_time) as firstTime max(_time) as lastTime by src user | where api_calls > 500 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has "Salesforce"
| where UserAgent has_any ("python-requests","simple-salesforce","python-urllib","Python/","aiohttp","httpx/")
| summarize ApiCalls = count(),
            DistinctObjects = dcount(ObjectName),
            DistinctActions = dcount(ActionType),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            UserAgents = make_set(UserAgent, 5),
            IPs = make_set(IPAddress, 10)
            by AccountDisplayName, AccountObjectId
| where ApiCalls > 500 or IPs has_any (IcarusIPs)
| extend SessionDurationHrs = datetime_diff('minute', LastSeen, FirstSeen) / 60.0
| order by ApiCalls desc
```

### Endpoint or network egress to Icarus operator IPs (Klue Salesforce breach C2)

`UC_3_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.dest_port) as ports sum(All_Traffic.bytes_in) as bytes_in sum(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where (All_Traffic.dest IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") OR All_Traffic.src IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160")) by All_Traffic.src All_Traffic.dest All_Traffic.user | `drop_dm_object_name("All_Traffic")` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (IcarusIPs)
| project Timestamp, DeviceName, DeviceId, ActionType, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### Inbound Icarus extortion email referencing Klue breach + Session messenger contact

`UC_3_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Email.subject) as subjects values(All_Email.body) as body_sample from datamodel=Email where All_Email.direction=inbound by All_Email.src_user All_Email.recipient | `drop_dm_object_name("All_Email")` | search (subjects="*Icarus*" OR subjects="*Klue*" OR body_sample="*Icarus*" OR body_sample="*Session*") AND (body_sample="*Session*" OR body_sample="*sessionid*" OR body_sample="*onion*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where Subject has_any ("Icarus","Klue breach","Klue.com","Salesforce data","data leak") 
    or AdditionalFields has_any ("Icarus","Session Messenger","sessionid")
| join kind=leftouter (
    EmailUrlInfo
    | where Timestamp > ago(30d)
    | summarize Urls = make_set(Url, 10), Domains = make_set(UrlDomain, 10) by NetworkMessageId
  ) on NetworkMessageId
| extend MentionsSession = tostring(AdditionalFields) has "Session" or tostring(Urls) has "getsession.org"
| where MentionsSession or Subject has "Icarus"
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, AuthenticationDetails, Urls, Domains
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `138.226.246.94`, `212.86.125.24`, `213.111.148.90`, `94.154.32.160`, `klue.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
