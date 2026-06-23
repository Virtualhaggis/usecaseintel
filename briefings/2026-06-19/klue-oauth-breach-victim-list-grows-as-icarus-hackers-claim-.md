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
- **T1567** — Exfiltration Over Web Service
- **T1213** — Data from Information Repositories
- **T1119** — Automated Collection
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Bulk Salesforce REST API exfiltration via compromised Klue OAuth token (high-volume query bursts)

`UC_28_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype IN (sfdc:eventlogfile, salesforce:eventlogfile, sfdc:event_log_file) (URI="*/services/data/*" OR URI="*sobjects*" OR URI="*/query*" OR EVENT_TYPE IN ("API","RestApi","BulkApi"))
| bin _time span=15m
| stats count AS api_calls, dc(URI) AS distinct_uris, values(USER_AGENT) AS user_agents, values(CLIENT_IP) AS src_ips by USER_ID, _time
| where api_calls > 900
| sort - api_calls
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let WindowMinutes = 15m;
let BurstThreshold = 900;            // ReliaQuest: ~1,000 Salesforce REST API calls / 15 min during Icarus exfil bursts
CloudAppEvents
| where Timestamp > ago(LookbackDays)
| where Application == "Salesforce"
| where tostring(RawEventData) has_any ("/services/data/", "sobjects", "/query", "queryMore")
| summarize ApiCalls = count(),
            DistinctObjects = dcount(ObjectName),
            UserAgents = make_set(UserAgent, 10),
            SourceIPs = make_set(IPAddress, 10),
            SampleActions = make_set(ActionType, 10)
        by AccountObjectId, AccountDisplayName, AccountType, bin(Timestamp, WindowMinutes)
| where ApiCalls > BurstThreshold
| order by ApiCalls desc
```

### Salesforce API access using Python-urllib automation agent (Icarus scripted CRM theft)

`UC_28_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype IN (sfdc:eventlogfile, salesforce:eventlogfile, sfdc:event_log_file) USER_AGENT="*Python-urllib*"
| stats count AS api_calls, values(URI) AS uris, values(CLIENT_IP) AS src_ips, min(_time) AS first_seen, max(_time) AS last_seen by USER_ID, USER_AGENT
| sort - api_calls
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application == "Salesforce"
| where UserAgent has "python-urllib"     // has is case-insensitive; covers Python-urllib casing
| summarize ApiCalls = count(),
            Objects = make_set(ObjectName, 15),
            Actions = make_set(ActionType, 10),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
        by AccountObjectId, AccountDisplayName, AccountType, IPAddress, ISP, CountryCode, UserAgent
| order by ApiCalls desc
```

### Salesforce access from known Icarus exfiltration IP addresses

`UC_28_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, min(_time) AS firstTime, max(_time) AS lastTime from datamodel=Authentication.Authentication where Authentication.app="salesforce" Authentication.src IN ("138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160") by Authentication.user, Authentication.src, Authentication.app
| `drop_dm_object_name(Authentication)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let IcarusIPs = dynamic(["138.226.246.94","212.86.125.24","213.111.148.90","94.154.32.160"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Salesforce"
| where IPAddress in (IcarusIPs)
| project Timestamp, AccountObjectId, AccountDisplayName, AccountType, IPAddress, ISP, CountryCode, IsAnonymousProxy, UserAgent, ActionType, ObjectName, ObjectType
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

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
