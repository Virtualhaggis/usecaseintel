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
- **T1114.003** — Email Collection: Email Forwarding Rule
- **T1098.002** — Account Manipulation: Additional Email Delegate Permissions
- **T1020** — Automated Exfiltration
- **T1505.003** — Server Software Component: Web Shell
- **T1554** — Compromise Host Software Binary
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1546** — Event Triggered Execution
- **T1114.002** — Email Collection: Remote Email Collection
- **T1567.002** — Exfiltration to Cloud Storage
- **T1132.001** — Data Encoding: Standard Encoding
- **T1573** — Encrypted Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### UNC6508 Google Workspace content compliance rule BCC'ing to external Gmail

`UC_5_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as object values(All_Changes.command) as command values(All_Changes.src) as src values(All_Changes.user) as admin from datamodel=Change where All_Changes.vendor_product IN ("Google Workspace","G Suite","Gmail") AND (All_Changes.action IN ("CHANGE_EMAIL_SETTING","CREATE_EMAIL_MONITOR","CONTENT_COMPLIANCE_RULE_CREATE","CREATE_GMAIL_SETTING") OR All_Changes.command IN ("CHANGE_EMAIL_SETTING","CREATE_EMAIL_MONITOR")) by All_Changes.user All_Changes.action All_Changes.object All_Changes.src _time | `drop_dm_object_name(All_Changes)` | search object="*Patroit*" OR object="*Patriot*" OR object="*chikungunya*" OR command="*@gmail.com*" OR object="*@gmail.com*" | table _time admin src action object command
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has_any ("Google Workspace","G Suite","Gmail")
| where IsAdminOperation == true
| where ActionType has_any ("CHANGE_EMAIL_SETTING","CREATE_EMAIL_MONITOR","CONTENT_COMPLIANCE","CREATE_GMAIL_SETTING","compliance_rule","EmailRouting","CHANGE_GMAIL_SETTING")
| extend RawData = tostring(RawEventData), AddData = tostring(AdditionalFields)
| where RawData has_any ("Patroit","Patriot","chikungunya","@gmail.com","BCC","bcc_address","add_x_header","monitor")
   or AddData has_any ("Patroit","chikungunya","@gmail.com")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, City,
          ActionType, ObjectName, ObjectType, ActivityType, RawEventData, AdditionalFields
| order by Timestamp desc
```

### INFINITERED REDCap backdoor SHA256 hash sweep

`UC_5_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as path values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7","db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136","c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b","8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec","51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045","4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b","58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86") by Processes.dest Processes.process_hash _time | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7","db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136","c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b","8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec","51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045","4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b","58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86") by Filesystem.dest Filesystem.file_hash _time | `drop_dm_object_name(Filesystem)`] | stats min(firstTime) as firstTime max(lastTime) as lastTime values(path) as paths by dest process_hash
```

**Defender KQL:**
```kql
let infinitered_sha256 = dynamic([
  "ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7",
  "db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136",
  "c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b",
  "8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec",
  "51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045",
  "4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b",
  "58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86"]);
union isfuzzy=true
  (DeviceFileEvents | where Timestamp > ago(180d) | where SHA256 in (infinitered_sha256) | project Timestamp, DeviceName, Source="FileEvent", ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
  (DeviceProcessEvents | where Timestamp > ago(180d) | where SHA256 in (infinitered_sha256) or InitiatingProcessSHA256 in (infinitered_sha256) | project Timestamp, DeviceName, Source="ProcessEvent", ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=AccountName),
  (DeviceImageLoadEvents | where Timestamp > ago(180d) | where SHA256 in (infinitered_sha256) | project Timestamp, DeviceName, Source="ImageLoad", ActionType, FolderPath, FileName, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=InitiatingProcessAccountName),
  (AlertEvidence | where Timestamp > ago(180d) | where SHA256 in (infinitered_sha256) | project Timestamp, DeviceName, Source="Alert", ActionType=EntityType, FolderPath, FileName, SHA256, InitiatingProcessFileName="", InitiatingProcessCommandLine="", InitiatingProcessAccountName=AccountName)
| order by Timestamp desc
```

### Network egress to UNC6508 C2 infrastructure (23.169.65.49)

`UC_5_8` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic where All_Traffic.dest="23.169.65.49" OR All_Traffic.dest_ip="23.169.65.49" by All_Traffic.dest All_Traffic.src All_Traffic.user _time | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(180d)
| where RemoteIP == "23.169.65.49"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, Protocol,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Trojanized REDCap PHP system-file modification (INFINITERED install)

`UC_5_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.file_name) as file values(Filesystem.user) as user values(Filesystem.process_name) as parent from datamodel=Endpoint.Filesystem where Filesystem.action IN ("modified","created","renamed") AND (Filesystem.file_path="*/redcap/*" OR Filesystem.file_path="*\\redcap\\*") AND Filesystem.file_name="*.php" AND NOT Filesystem.process_name IN ("apt","apt-get","dpkg","yum","dnf","rpm","composer","php-fpm","git","tar","unzip","msiexec.exe","trustedinstaller.exe") by Filesystem.dest Filesystem.file_path Filesystem.process_name _time | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(180d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("/redcap/","\\redcap\\","/redcap_v","\\redcap_v")
| where FileName endswith ".php"
| where InitiatingProcessFileName !in~ ("apt","apt-get","dpkg","yum","dnf","rpm","composer","php-fpm","php","git","tar","unzip","gunzip","sshd","rsync","msiexec.exe","trustedinstaller.exe")
| where InitiatingProcessFolderPath !startswith "/usr/lib/apt" and InitiatingProcessFolderPath !startswith "/usr/bin/dpkg"
| extend SuspiciousFile = iff(FileName matches regex @"(?i)(login|index|init_functions|system|database|upgrade|home)\.php$", true, false)
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256, SuspiciousFile,
          InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by SuspiciousFile desc, Timestamp desc
```

### Bulk Gmail export / Takeout immediately following Workspace admin rule change

`UC_5_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats `summariesonly` count min(_time) as ruleTime from datamodel=Change where All_Changes.vendor_product IN ("Google Workspace","G Suite") AND All_Changes.action IN ("CHANGE_EMAIL_SETTING","CREATE_EMAIL_MONITOR","CONTENT_COMPLIANCE_RULE_CREATE","CREATE_GMAIL_SETTING") by All_Changes.user All_Changes.src _time | `drop_dm_object_name(All_Changes)` | rename user as admin | join type=inner admin [| tstats `summariesonly` count min(_time) as exportTime values(All_Changes.object) as object from datamodel=Change where All_Changes.vendor_product IN ("Google Workspace","G Suite") AND All_Changes.action IN ("TAKEOUT_REQUEST_CREATE","DOWNLOAD_USER_DATA","GMAIL_RESERVED_KEYWORD_EXPORT","DATA_EXPORT_INITIATED","USER_TAKEOUT") by All_Changes.user _time | `drop_dm_object_name(All_Changes)` | rename user as admin] | where exportTime >= ruleTime AND exportTime <= ruleTime + 604800 | table admin src ruleTime exportTime object
```

**Defender KQL:**
```kql
let lookback = 30d;
let WindowDays = 7d;
let RuleChanges = CloudAppEvents
  | where Timestamp > ago(lookback)
  | where Application has_any ("Google Workspace","G Suite","Gmail")
  | where IsAdminOperation == true
  | where ActionType has_any ("CHANGE_EMAIL_SETTING","CREATE_EMAIL_MONITOR","CONTENT_COMPLIANCE","CREATE_GMAIL_SETTING","EmailRouting")
  | project RuleTime = Timestamp, RuleAdmin = AccountDisplayName, RuleAdminObjectId = AccountObjectId, RuleAction = ActionType, RuleSrcIP = IPAddress, RuleData = tostring(RawEventData);
let Exports = CloudAppEvents
  | where Timestamp > ago(lookback)
  | where Application has_any ("Google Workspace","G Suite","Gmail","Google Takeout")
  | where ActionType has_any ("DOWNLOAD_USER_DATA","TAKEOUT","USER_TAKEOUT","DATA_EXPORT","GMAIL_RESERVED_KEYWORD_EXPORT","DataExport")
  | project ExportTime = Timestamp, ExportActor = AccountDisplayName, ExportActorObjectId = AccountObjectId, ExportAction = ActionType, ExportSrcIP = IPAddress, ExportData = tostring(RawEventData);
RuleChanges
| join kind=inner Exports on $left.RuleAdminObjectId == $right.ExportActorObjectId
| where ExportTime between (RuleTime .. RuleTime + WindowDays)
| extend DelayHours = datetime_diff('hour', ExportTime, RuleTime)
| project RuleTime, ExportTime, DelayHours, RuleAdmin, RuleSrcIP, ExportSrcIP, RuleAction, ExportAction, RuleData, ExportData
| order by RuleTime desc
```

### Anomalous HTTP cookie payload to REDCap endpoints (INFINITERED C2 channel)

`UC_5_11` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats `summariesonly` count from datamodel=Web where Web.url="*/redcap/*" OR Web.uri_path="*/redcap/*" by Web.src Web.dest Web.url Web.user_agent Web.http_method _time _raw | `drop_dm_object_name(Web)` | rex field=_raw "(?i)Cookie:\s*(?<cookie_header>[^\r\n]+)" | eval cookie_len=len(cookie_header) | where cookie_len > 512 | eval looks_b64=if(match(cookie_header,"[A-Za-z0-9+/=]{200,}"),1,0) | where looks_b64=1 OR cookie_len > 1024 | table _time src dest url user_agent cookie_len cookie_header
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

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
