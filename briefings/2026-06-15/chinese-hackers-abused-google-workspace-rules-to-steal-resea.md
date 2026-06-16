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
- **T1573** — Encrypted Channel
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1098.002** — Account Manipulation: Additional Email Delegate Permissions
- **T1556** — Modify Authentication Process
- **T1114.002** — Email Collection: Remote Email Collection
- **T1020** — Automated Exfiltration
- **T1567** — Exfiltration Over Web Service
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### INFINITERED PHP trojanization of REDCap system files

`UC_6_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created OR Filesystem.action=modified (Filesystem.file_path="*/redcap/*" OR Filesystem.file_path="*/redcap_v*/*") (Filesystem.file_name="*.php" OR Filesystem.file_name="index.php" OR Filesystem.file_name="Authentication.php" OR Filesystem.file_name="Logging.php") (Filesystem.process_name="httpd" OR Filesystem.process_name="apache2" OR Filesystem.process_name="nginx" OR Filesystem.process_name="php-fpm*" OR Filesystem.process_name="www-data") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name Filesystem.file_hash | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FolderPath has_any ("/redcap/", "/redcap_v", "\\redcap\\", "\\redcap_v")
| where FileName endswith ".php" or FileName endswith ".inc"
| where InitiatingProcessFileName in~ ("httpd","apache2","nginx","php-fpm","php-fpm8.1","php-fpm8.2","w3wp.exe","php-cgi.exe")
   or InitiatingProcessAccountName in~ ("www-data","apache","nginx","httpd")
| project Timestamp, DeviceName, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessAccountName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### INFINITERED HTTP cookie command-and-control on REDCap web server

`UC_6_7` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.dest_category="redcap" OR Web.url="*/redcap/*" OR Web.url="*/redcap_v*" by Web.src Web.dest Web.url Web.http_user_agent Web.http_method Web.cookie | `drop_dm_object_name(Web)`
| where like(cookie,"%=%") AND (len(cookie) > 200 OR match(cookie,"^[A-Za-z0-9+/=]{120,}$"))
| join type=inner src [search index=network src_ip="23.169.65.49" earliest=-30d | stats values(src_ip) as src by src]
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "23.169.65.49" or LocalIP == "23.169.65.49"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, LocalIP, LocalPort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### Google Workspace content compliance rule BCC to external Gmail (UNC6508 'Patroit')

`UC_6_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gws_admin_audit` event.type="GSUITE_ADMIN" (event.name="CHANGE_GMAIL_SETTING" OR event.name="CREATE_GMAIL_SETTING" OR event.name="CREATE_APPLICATION_SETTING" OR event.name="CHANGE_APPLICATION_SETTING") (parameters.SETTING_NAME="CONTENT_COMPLIANCE" OR parameters.APPLICATION_NAME="Gmail")
| eval rule_name=coalesce('parameters.RULE_NAME','parameters.SETTING_DESCRIPTION')
| eval rule_body=coalesce('parameters.NEW_VALUE','parameters.VALUE')
| where match(lower(rule_body),"bcc|forward|address\\s*added") AND match(lower(rule_body),"@gmail\\.com|@outlook\\.com|@proton(mail)?\\.com|@yandex|@yahoo\\.com")
  OR match(lower(rule_name),"patroit|patriot|chikungunya")
| stats min(_time) as firstTime max(_time) as lastTime values(rule_name) as rule values(rule_body) as rule_body by actor.email ipAddress
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(90d)
| where Application has_any ("Google Workspace","GSuite","Google")
| where ActionType has_any ("CHANGE_APPLICATION_SETTING","CREATE_APPLICATION_SETTING","CHANGE_GMAIL_SETTING","CREATE_GMAIL_SETTING","content_compliance")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("CONTENT_COMPLIANCE","content_compliance","contentCompliance")
| extend RuleName = tostring(parse_json(Raw).parameters.RULE_NAME),
         RuleBody = tostring(parse_json(Raw).parameters.NEW_VALUE)
| where RuleBody has_any ("bcc","forward","address_added") and RuleBody matches regex @"(?i)@(gmail|outlook|proton(mail)?|yandex|yahoo)\.com"
   or RuleName matches regex @"(?i)patroit|patriot|chikungunya"
| project Timestamp, AccountDisplayName, AccountId, IPAddress, ActionType,
          RuleName, RuleBody, CountryCode, UserAgent
| order by Timestamp desc
```

### GWS user-level forwarding/delegation to external free-mail provider

`UC_6_9` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gws_gmail_audit` (event.name="email_forwarding_out_of_domain" OR event.name="email_log_search" OR event.name="GRANT_DELEGATED_ACCESS" OR event.name="CREATE_EMAIL_MONITOR" OR event.name="forwarding_address_added" OR event.name="filter_creation")
| rex field=parameters.FORWARDING_ADDRESS "@(?<dst_domain>[^>\"]+)"
| eval dst_domain=coalesce(dst_domain, mvindex(split(coalesce('parameters.DELEGATED_USER_EMAIL','parameters.EMAIL_MONITOR_DEST_EMAIL'),"@"),1))
| where match(lower(dst_domain),"^(gmail|outlook|hotmail|protonmail|proton|tutanota|yandex|yahoo|mail\\.ru|qq|163|126|sina)\\.")
| stats min(_time) as firstTime max(_time) as lastTime values(dst_domain) as dst by actor.email ipAddress event.name
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(60d)
| where Application has_any ("Google Workspace","GSuite","Gmail")
| where ActionType in ("email_forwarding_out_of_domain","forwarding_address_added","filter_creation","GRANT_DELEGATED_ACCESS","CREATE_EMAIL_MONITOR")
| extend Raw = tostring(RawEventData)
| extend Target = extract(@"(?i)(?:FORWARDING_ADDRESS|DELEGATED_USER_EMAIL|EMAIL_MONITOR_DEST_EMAIL|forwardingAddress)\W+[\"']?([^\"',}\s]+@[^\"',}\s]+)",1,Raw)
| where Target matches regex @"(?i)@(gmail|outlook|hotmail|protonmail|proton|tutanota|yandex|yahoo|mail\.ru|qq|163|126|sina)\."
| project Timestamp, AccountDisplayName, AccountId, IPAddress, CountryCode,
          UserAgent, ActionType, Target, Raw
| order by Timestamp desc
```

### Bulk mailbox export or Takeout following recent forwarding/rule change

`UC_6_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gws_admin_audit`
| eval is_rule=if(match(event.name,"(?i)CONTENT_COMPLIANCE|forwarding_address_added|GRANT_DELEGATED_ACCESS|filter_creation|CREATE_EMAIL_MONITOR"),1,0),
       is_export=if(match(event.name,"(?i)TAKEOUT|VAULT_EXPORT|DATA_EXPORT|DOWNLOAD_USER_DATA|EXPORT_REPORT"),1,0)
| stats min(_time) as t_rule by actor.email is_rule | where is_rule=1
| join actor.email [
    search `gws_admin_audit`
    | where match(event.name,"(?i)TAKEOUT|VAULT_EXPORT|DATA_EXPORT|DOWNLOAD_USER_DATA|EXPORT_REPORT")
    | rename _time as t_export]
| where t_export between (t_rule AND t_rule+604800)
| table actor.email t_rule t_export event.name parameters.*
```

**Defender KQL:**
```kql
let RuleEvents = CloudAppEvents
    | where Timestamp > ago(60d)
    | where Application has_any ("Google Workspace","GSuite","Gmail")
    | where ActionType matches regex @"(?i)CONTENT_COMPLIANCE|forwarding_address_added|GRANT_DELEGATED_ACCESS|filter_creation|CREATE_EMAIL_MONITOR"
    | project RuleTime = Timestamp, AccountId, AccountDisplayName, IPAddress, RuleAction = ActionType;
let Exports = CloudAppEvents
    | where Timestamp > ago(60d)
    | where Application has_any ("Google Workspace","GSuite","Vault","Takeout")
    | where ActionType matches regex @"(?i)TAKEOUT|VAULT_EXPORT|DATA_EXPORT|DOWNLOAD_USER_DATA|EXPORT_REPORT"
    | project ExportTime = Timestamp, AccountId, ExportAction = ActionType, ExportIP = IPAddress, ObjectName;
RuleEvents
| join kind=inner Exports on AccountId
| where ExportTime between (RuleTime .. RuleTime + 7d)
| project AccountDisplayName, AccountId, RuleTime, RuleAction, IPAddress,
          ExportTime, ExportAction, ExportIP, ObjectName
| order by ExportTime desc
```

### GWS super-admin account accessing many distinct mailboxes in a short window

`UC_6_11` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`gws_gmail_audit` event.name IN ("email_log_search","message_access","mail_lookup","mailbox_login")
| bucket _time span=1h
| stats dc(parameters.user_email) as victims_touched values(parameters.user_email) as victims by actor.email _time ipAddress
| where victims_touched >= 10
| `security_content_ctime(_time)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any ("Google Workspace","GSuite","Gmail")
| where ActionType in ("email_log_search","message_access","mail_lookup","mailbox_login")
| extend VictimMailbox = tostring(parse_json(tostring(RawEventData)).parameters.user_email)
| where isnotempty(VictimMailbox) and AccountId != VictimMailbox
| summarize VictimsTouched = dcount(VictimMailbox),
            Victims = make_set(VictimMailbox, 50),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp)
          by AccountId, AccountDisplayName, IPAddress, bin(Timestamp, 1h)
| where VictimsTouched >= 10
| order by LastSeen desc
```

### INFINITERED known-hash file or process IOC sweep

`UC_6_12` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint where (Processes.process_hash IN ("ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7","db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136","c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b","8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec","51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045","4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b","58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86")) OR (Filesystem.file_hash IN ("ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7","db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136","c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b","8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec","51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045","4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b","58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86")) by host process_name file_name file_hash process_hash | `drop_dm_object_name(Endpoint)`
```

**Defender KQL:**
```kql
let IOCs = dynamic([
  "ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7",
  "db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136",
  "c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b",
  "8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec",
  "51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045",
  "4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b",
  "58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86"
]);
union isfuzzy=true
(DeviceFileEvents
   | where Timestamp > ago(365d) | where SHA256 in (IOCs)
   | project Timestamp, Source="FileEvent", DeviceName, FileName, FolderPath, SHA256,
             InitiatingProcessFileName, InitiatingProcessAccountName),
(DeviceProcessEvents
   | where Timestamp > ago(365d) | where SHA256 in (IOCs) or InitiatingProcessSHA256 in (IOCs)
   | project Timestamp, Source="Process", DeviceName, FileName, FolderPath, SHA256,
             ProcessCommandLine, AccountName),
(DeviceNetworkEvents
   | where Timestamp > ago(365d) | where RemoteIP == "23.169.65.49"
   | project Timestamp, Source="Network", DeviceName, RemoteIP, RemotePort, RemoteUrl,
             InitiatingProcessFileName, InitiatingProcessAccountName)
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
