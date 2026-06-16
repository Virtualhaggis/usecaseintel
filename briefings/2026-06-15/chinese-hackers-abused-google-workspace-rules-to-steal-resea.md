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
- **T1098.002** — Account Manipulation: Additional Email Delegate Permissions
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1556** — Modify Authentication Process
- **T1213** — Data from Information Repositories
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1505.003** — Server Software Component: Web Shell
- **T1554** — Compromise Host Software Binary
- **T1546** — Event Triggered Execution
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1530** — Data from Cloud Storage Object
- **T1114.002** — Email Collection: Remote Email Collection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### UNC6508 Google Workspace Domain Content Compliance Rule with External BCC

`UC_43_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as object values(All_Changes.user) as user values(All_Changes.src) as src from datamodel=Change.All_Changes where All_Changes.vendor_product="Google Workspace" (All_Changes.action=created OR All_Changes.action=modified) (All_Changes.object_category="compliance_rule" OR All_Changes.object_category="content_compliance" OR All_Changes.change_type="GSUITE_ADMIN") by All_Changes.user All_Changes.object All_Changes.object_path | `drop_dm_object_name(All_Changes)` | search object_path="*bcc*" OR object_path="*@gmail.com*" OR object_path="*forward*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_cs "Google"
| where IsAdminOperation == true
| where ActionType has_any ("CREATE_GMAIL_SETTING","CHANGE_GMAIL_SETTING","Create rule","Update rule","compliance","CREATE_APPLICATION_SETTING","CHANGE_APPLICATION_SETTING")
| extend RawText = tostring(RawEventData)
| where RawText has_any ("content_compliance","CONTENT_COMPLIANCE","content compliance","contentCompliance")
| where RawText has_any ("BCC","Bcc","bcc","forward","copyMessage")
| where RawText has "gmail.com" or RawText matches regex @"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
| project Timestamp, AccountDisplayName, AccountId, AccountObjectId, IPAddress, CountryCode, ActionType, ObjectName, RawText
```

### UNC6508 Content Compliance Rule with Espionage Keywords (Patroit / chikungunya)

`UC_43_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object_path) as object_path values(All_Changes.user) as user values(All_Changes.src) as src from datamodel=Change.All_Changes where All_Changes.vendor_product="Google Workspace" by All_Changes.user All_Changes.object | `drop_dm_object_name(All_Changes)` | search object_path="*Patroit*" OR object_path="*chikungunya*" OR object_path="*Guangdong*" OR object_path="*uncrewed*" OR object_path="*offensive cyber*" OR object_path="*FOUO*" OR object_path="*CUI*" OR object_path="*ITAR*" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(90d)
| where Application has_cs "Google"
| where IsAdminOperation == true
| where ActionType has_any ("CREATE_GMAIL_SETTING","CHANGE_GMAIL_SETTING","Create rule","Update rule","compliance","CREATE_APPLICATION_SETTING")
| extend RawText = tostring(RawEventData)
| where RawText has_any ("Patroit","chikungunya","Guangdong","uncrewed","unmanned aerial","offensive cyber","FOUO","CUI","ITAR","controlled unclassified")
| project Timestamp, AccountDisplayName, AccountId, IPAddress, CountryCode, ActionType, ObjectName, RawText
```

### Outbound Connection to UNC6508 C2 Infrastructure (23.169.65.49)

`UC_43_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.src_port) as src_port values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="23.169.65.49" OR All_Traffic.src="23.169.65.49") by All_Traffic.src All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteIP == "23.169.65.49" or LocalIP == "23.169.65.49"
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemoteIP, RemotePort, LocalPort, Protocol, RemoteUrl
| order by Timestamp desc
```

### INFINITERED Trojanized REDCap System File on Disk (SHA256)

`UC_43_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.user) as user values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7","db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136","c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b","8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec","51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045","4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b","58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86") by Filesystem.dest Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let INFINITERED_HASHES = dynamic(["ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7","db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136","c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b","8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec","51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045","4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b","58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86"]);
union isfuzzy=true
(DeviceFileEvents
  | where Timestamp > ago(180d)
  | where SHA256 in (INFINITERED_HASHES)
  | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceProcessEvents
  | where Timestamp > ago(180d)
  | where SHA256 in (INFINITERED_HASHES) or InitiatingProcessSHA256 in (INFINITERED_HASHES)
  | project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName)
```

### Gmail User-Level Forwarding/Filter Rule to External Address

`UC_43_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object_path) as object_path values(All_Changes.user) as user values(All_Changes.src) as src from datamodel=Change.All_Changes where All_Changes.vendor_product="Google Workspace" (All_Changes.action=created OR All_Changes.action=modified) (All_Changes.object_category="filter" OR All_Changes.object_category="forward" OR All_Changes.change_type="USER_SETTINGS") by All_Changes.user All_Changes.object | `drop_dm_object_name(All_Changes)` | rex field=object_path "forward.{0,40}@(?<forward_domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})" | search forward_domain!="yourorg.com" forward_domain!="yourorg.org" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CorporateDomains = dynamic(["yourorg.com","yourorg.org"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_cs "Google"
| where ActionType has_any ("email_forwarding_out_of_domain","Create Filter","Email forwarding","FORWARDING_RULE","CHANGE_USER_SETTING")
| extend RawText = tostring(RawEventData)
| where RawText has_any ("forward","forwardingAddress","FORWARD")
| extend FwdDomain = tolower(extract(@"forward[^@]{0,40}@([A-Za-z0-9.-]+\.[A-Za-z]{2,})", 1, RawText))
| where isnotempty(FwdDomain)
| where not(FwdDomain in (CorporateDomains))
| project Timestamp, AccountDisplayName, AccountId, IPAddress, CountryCode, ActionType, ObjectName, FwdDomain, RawText
```

### Gmail Mailbox Delegation Granted to External Principal

`UC_43_11` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.object) as object values(All_Changes.object_path) as object_path values(All_Changes.src) as src from datamodel=Change.All_Changes where All_Changes.vendor_product="Google Workspace" (All_Changes.change_type="DELEGATE" OR All_Changes.action="CREATE_DELEGATE" OR All_Changes.action="ADD_DELEGATE") by All_Changes.user All_Changes.object | `drop_dm_object_name(All_Changes)` | rex field=object_path "delegate.{0,40}@(?<delegate_domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})" | search delegate_domain!="yourorg.com" | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CorporateDomains = dynamic(["yourorg.com","yourorg.org"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_cs "Google"
| where ActionType has_any ("CREATE_DELEGATE","ADD_DELEGATE","DELEGATE_EMAIL","Add mail delegate","mail.delegate")
| extend RawText = tostring(RawEventData)
| extend DelegateAddr = tolower(extract(@"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", 1, RawText))
| extend DelegateDomain = tostring(split(DelegateAddr, "@")[1])
| where isnotempty(DelegateDomain) and not(DelegateDomain in (CorporateDomains))
| project Timestamp, AccountDisplayName, AccountId, IPAddress, CountryCode, ActionType, ObjectName, DelegateAddr, DelegateDomain, RawText
```

### Admin/Service Account Mailbox Fan-Out (Mass Mailbox Access in Short Window)

`UC_43_12` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(All_Changes.object) as distinct_mailboxes min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as mailboxes values(All_Changes.src) as src from datamodel=Change.All_Changes where All_Changes.vendor_product="Google Workspace" All_Changes.user_category="admin" by All_Changes.user span=1h | `drop_dm_object_name(All_Changes)` | where distinct_mailboxes >= 10 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application has_cs "Google"
| where IsAdminOperation == true or AccountType has_any ("admin","service")
| where ActionType has_any ("View Item","Access","Read mailbox","List Messages","GET_MAILBOX","Impersonate")
| summarize DistinctMailboxes = dcount(ObjectId), Mailboxes = make_set(ObjectName, 50), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SrcIPs = make_set(IPAddress, 10), UAs = make_set(UserAgent, 10) by AccountDisplayName, AccountId, bin(Timestamp, 1h)
| where DistinctMailboxes >= 10
| order by Timestamp desc
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

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
