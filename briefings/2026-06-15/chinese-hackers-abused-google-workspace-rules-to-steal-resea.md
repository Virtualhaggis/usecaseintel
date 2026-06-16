# [CRIT] Chinese Hackers Abused Google Workspace Rules to Steal Research and Defense Emails

**Source:** The Hacker News
**Published:** 2026-06-15
**Article:** https://thehackernews.com/2026/06/chinese-hackers-abused-google-workspace.html

## Threat Profile

Chinese Hackers Abused Google Workspace Rules to Steal Research and Defense Emails 
 Swati Khandelwal  Jun 15, 2026 Cyber Espionage / Email Security 
A China-linked espionage group hid inside North American medical, academic, and military research networks for more than a year, quietly stealing sensitive research and defense email.
The way in was a backdoor on their REDCap research servers that stole login credentials. The exfiltration was the unusual part: the attackers rewired the victims' o…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `23.169.65.49`
- **SHA256:** `ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7`
- **SHA256:** `db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136`
- **SHA256:** `c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b`
- **SHA256:** `8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec`
- **SHA256:** `51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045`
- **SHA256:** `4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b`
- **SHA256:** `58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86`

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
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1505.003** — Server Software Component: Web Shell
- **T1554** — Compromise Host Software Binary
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1114.002** — Email Collection: Remote Email Collection
- **T1098.002** — Account Manipulation: Additional Email Delegate Permissions
- **T1020** — Automated Exfiltration
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1098.004** — Account Manipulation: SSH Authorized Keys / Mail Delegation
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1530** — Data from Cloud Storage Object

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### INFINITERED REDCap backdoor SHA256 file write on web server

`UC_6_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.action=created AND Endpoint.Filesystem.file_hash IN ("ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7","db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136","c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b","8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec","51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045","4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b","58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86") by Endpoint.Filesystem.dest Endpoint.Filesystem.file_name Endpoint.Filesystem.file_path Endpoint.Filesystem.process_name Endpoint.Filesystem.user | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(90d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where SHA256 in (
    "ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7",
    "db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136",
    "c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b",
    "8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec",
    "51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045",
    "4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b",
    "58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Outbound connection to UNC6508 C2 IP 23.169.65.49

`UC_6_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime from datamodel=Network_Traffic where All_Traffic.dest_ip="23.169.65.49" by All_Traffic.src All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.user All_Traffic.transport | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP == "23.169.65.49"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, Protocol, LocalIP, LocalPort
| order by Timestamp desc
```

### Google Workspace content compliance rule containing UNC6508 espionage keywords

`UC_6_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Change where Change.action=created AND (Change.object_category=email_rule OR Change.object_category=workspace_policy OR Change.object_category=mail_routing) by Change.user Change.src Change.object Change.command Change.result | `drop_dm_object_name(Change)` | eval keyword_match=if(match(lower(command), "patroit|chikungunya|uncrewed|geo-strategic|offensive cyber|military strategy|advanced technology"), 1, 0) | where keyword_match=1 | table _time user src object command
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(90d)
| where Application has_any ("Google Workspace","Google Apps","Gmail","Google")
| where ActionType has_any ("CREATE_GMAIL_SETTING","CHANGE_GMAIL_SETTING","CREATE_APPLICATION_SETTING","CHANGE_APPLICATION_SETTING","content_compliance_rule_created","CREATE_FILTER")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("Patroit","chikungunya","uncrewed","offensive cyber","geo-strategic","military strategy","advanced technology")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, IsAdminOperation, ActionType, ObjectName, Raw
| order by Timestamp desc
```

### Google Workspace mail rule with BCC or forward to external personal mail provider

`UC_6_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Change where Change.action=created AND (Change.object_category=email_rule OR Change.object_category=mail_routing OR Change.object_category=email_forwarding) by Change.user Change.src Change.object Change.command | `drop_dm_object_name(Change)` | eval has_bcc_or_fwd=if(match(lower(command), "bcc|forward|content_compliance|add_forwarding_address"), 1, 0) | eval external_personal=if(match(lower(command), "@gmail\.com|@outlook\.com|@hotmail\.com|@yahoo\.com|@protonmail\.com|@proton\.me|@yandex\.com|@163\.com|@qq\.com"), 1, 0) | where has_bcc_or_fwd=1 AND external_personal=1 | table _time user src object command
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any ("Google Workspace","Google Apps","Gmail")
| where ActionType has_any ("CREATE_GMAIL_SETTING","CHANGE_GMAIL_SETTING","CREATE_APPLICATION_SETTING","CHANGE_APPLICATION_SETTING","CREATE_FILTER","ADD_FORWARDING_ADDRESS","UPDATE_FORWARDING_ADDRESS")
| extend Raw = tostring(RawEventData)
| where Raw matches regex @"(?i)bcc|forward|content_compliance|add_forwarding_address"
| where Raw matches regex @"(?i)@(gmail|outlook|hotmail|yahoo|protonmail|proton\.me|yandex|163|qq)\.(com|me)"
| project Timestamp, AccountDisplayName, IPAddress, CountryCode, IsAdminOperation, ActionType, ObjectName, Raw
| order by Timestamp desc
```

### Google Workspace mailbox delegation grant to non-corporate principal

`UC_6_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Change where Change.action IN (created,modified) AND (Change.object_category=mail_delegation OR Change.object_category=mailbox_permission) by Change.user Change.src Change.object Change.command Change.result | `drop_dm_object_name(Change)` | rex field=command "(?<delegate>[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})" | eval external=if(match(lower(delegate), "@(gmail|outlook|hotmail|yahoo|protonmail|proton\.me|yandex|163|qq)\.(com|me)"), 1, 0) | where external=1 | table _time user src object delegate command
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(90d)
| where Application has_any ("Google Workspace","Google Apps","Gmail")
| where ActionType has_any ("CHANGE_MAIL_DELEGATION","CREATE_MAIL_DELEGATION","ADD_MAIL_DELEGATION","GRANT_DELEGATED_MAILBOX_ACCESS","CHANGE_USER_MAILBOX_DELEGATE","AUTHORIZE_DELEGATE_USER")
| extend Raw = tostring(RawEventData)
| extend Delegate = extract(@"(?i)([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", 1, Raw)
| where Delegate matches regex @"(?i)@(gmail|outlook|hotmail|yahoo|protonmail|proton\.me|yandex|163|qq)\.(com|me)"
| project Timestamp, AccountDisplayName, IPAddress, CountryCode, IsAdminOperation, ActionType, ObjectName, Delegate, Raw
| order by Timestamp desc
```

### Google Workspace admin or service account reading 10+ distinct mailboxes within 1 hour

`UC_6_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`google_workspace_audit` (eventName="email_log_search" OR eventName="mailbox_access" OR eventName="CHANGE_GMAIL_SETTING" OR eventName="CREATE_GMAIL_SETTING" OR eventName="VAULT_SEARCH") | bucket _time span=1h | stats dcount(target_user) as mailboxes values(eventName) as actions earliest(_time) as firstSeen latest(_time) as lastSeen by user src_ip _time | where mailboxes >= 10
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_any ("Google Workspace","Google Apps","Gmail")
| where ActionType has_any ("email_log_search","mailbox_access","CHANGE_GMAIL_SETTING","CREATE_GMAIL_SETTING","VAULT_SEARCH","MAILBOX_ACCESS","AccessMailbox")
| summarize Mailboxes = dcount(ObjectName), SampleActions = make_set(ActionType, 20), SampleMailboxes = make_set(ObjectName, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountDisplayName, AccountObjectId, IPAddress, bin(Timestamp, 1h)
| where Mailboxes >= 10
| order by Mailboxes desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `23.169.65.49`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7`, `db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136`, `c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b`, `8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec`, `51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045`, `4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b`, `58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
