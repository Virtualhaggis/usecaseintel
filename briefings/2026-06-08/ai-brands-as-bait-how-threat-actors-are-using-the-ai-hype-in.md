# [CRIT] AI brands as bait: How threat actors are using the AI hype in social engineering

**Source:** Microsoft Security Blog
**Published:** 2026-06-08
**Article:** https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-the-ai-hype-in-social-engineering/

## Threat Profile

Tags 
Adversary-in-the-middle (AiTM) 
Credential theft 
Threats intelligence 
AI threats 
Cybercrime 
Social engineering and phishing 
Content types 
Research 
Products and services 
Microsoft Defender 
Microsoft Defender for Cloud Apps 
Microsoft Defender for Endpoint 
Microsoft Defender for Identity 
Microsoft Defender for Office 365 
Microsoft Entra ID Protection 
Topics 
Actionable threat insights 
Threat intelligence 
As threat actors operationalize AI to accelerate attacks, they are also l…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `legendarytrendsbay.shop`
- **Domain (defanged):** `dash.awaydouble.org`
- **Domain (defanged):** `awaydouble.org`
- **Domain (defanged):** `servicing.pureplantcravings.com`
- **Domain (defanged):** `pureplantcravings.com`
- **Domain (defanged):** `brokeapt.com`
- **Domain (defanged):** `pan.ssffaa19.xyz`
- **Domain (defanged):** `ssffaa19.xyz`
- **Domain (defanged):** `pan.rongtv.xyz`
- **Domain (defanged):** `rongtv.xyz`
- **SHA256:** `791efb555eefb7215e96659a1353a97416743b66bdd72705493129c64057d40e`
- **SHA256:** `c7c5072df9f83f4c440a5c3bb4be1d5f6c67bbf78f196406ca20d27b43b975b8`
- **SHA256:** `0a26238f6c516de5885457c93042531aa59bc206a9537cebf5267cedc6c68531`
- **SHA256:** `8610d4fb0ec5b525071c2aaec4df0f8fcbb3673aba58a7e1959fc44e83c0e2ca`
- **SHA256:** `99231deb373997364381d1eb513d2d42231d418c3a2db9007c5af9bd56ab9371`
- **SHA256:** `25270cc429ada8028b5b33220ed412c47907ecceea7377d608fac5af01bed56a`
- **SHA256:** `56d722b0331bf0aaa86bb37483486c6dff6ad9427fc473ed7c3226c21a9bdd23`
- **SHA256:** `5455341ed1bbe75a664fca2dd0794c508e1874f75360253a7ff5bc119bc92d80`
- **SHA1:** `4f5c5b3ef45cfff7721754487a86aeff9a2e6e32`
- **MD5:** `fbfe7513685913e6f878647eec429d45`
- **MD5:** `562d48524313d414b5a419fed6ca10aa`
- **MD5:** `b96c0d609c1b7e74f8cb1442bf0b5418`
- **MD5:** `dbaa133fd3d1a834460206d83b480f80`
- **MD5:** `22c0c7d441fd22432cfe7854b59ba82b`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1656** — Impersonation
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1557** — Adversary-in-the-Middle
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1608.005** — Stage Capabilities: Link Target
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### ChatGPT Plus payment-update phishing emails (display-name + subject lure)

`UC_67_12` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where (Email.src_user_display="ChatGPT*" OR Email.subject="*ChatGPT Plus*") (Email.subject="*payment method*" OR Email.subject="*continues to work*" OR Email.subject="*downgraded*") by Email.src_user, Email.src_user_display, Email.recipient, Email.subject, Email.message_id | `drop_dm_object_name(Email)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(14d)
| where (SenderDisplayName =~ "ChatGPT" or SenderFromAddress has "chatgpt")
    and Subject has "ChatGPT Plus"
    and Subject has_any ("payment method","continues to work","update your payment","downgraded","free plan")
| where SenderFromDomain !endswith "openai.com"
| join kind=leftouter (EmailUrlInfo | project NetworkMessageId, Url, UrlDomain) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName, SenderFromDomain, RecipientEmailAddress, Subject, Url, UrlDomain, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

### Claude 'Appeal Request' phishing email with PDF attachment lure

`UC_67_13` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where (Email.src_user_display IN ("Anthropic Teams","Anthropic PBC") OR Email.subject="*Claude Appeal Request*" OR Email.file_name="Fill and Sign Claude Appeal Form.pdf") by Email.src_user, Email.src_user_display, Email.recipient, Email.subject, Email.file_name, Email.message_id | `drop_dm_object_name(Email)` | search (src_user_display IN ("Anthropic Teams","Anthropic PBC") OR file_name="Fill and Sign Claude Appeal Form.pdf") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let suspect_mail = EmailEvents
    | where Timestamp > ago(30d)
    | where SenderDisplayName in~ ("Anthropic Teams","Anthropic PBC")
         or Subject matches regex @"(?i)Claude\s+Appeal\s+Request"
    | where SenderFromDomain !endswith "anthropic.com";
let suspect_attach = EmailAttachmentInfo
    | where Timestamp > ago(30d)
    | where FileType =~ "pdf"
    | where FileName =~ "Fill and Sign Claude Appeal Form.pdf"
         or FileName matches regex @"(?i)(Claude|Anthropic).{0,20}Appeal.{0,20}Form.*\.pdf$";
suspect_mail
| join kind=inner suspect_attach on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName, SenderFromDomain, RecipientEmailAddress, Subject, FileName, FileSize, SHA256, DeliveryAction, DeliveryLocation
| order by Timestamp desc
```

### Connection to AI-brand phishing / installer C2 infrastructure (MSTI June 2026 IOCs)

`UC_67_14` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.src) as src values(All_Traffic.dest_ip) as dest_ip from datamodel=Network_Traffic where (All_Traffic.dest IN ("legendarytrendsbay.shop","dash.awaydouble.org","awaydouble.org","servicing.pureplantcravings.com","pureplantcravings.com","brokeapt.com","pan.ssffaa19.xyz","ssffaa19.xyz")) by All_Traffic.dest, All_Traffic.app | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let ioc_domains = dynamic(["legendarytrendsbay.shop","dash.awaydouble.org","awaydouble.org","servicing.pureplantcravings.com","pureplantcravings.com","brokeapt.com","pan.ssffaa19.xyz","ssffaa19.xyz"]);
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where isnotempty(RemoteUrl)
| extend host = tolower(tostring(parse_url(RemoteUrl).Host))
| where host in (ioc_domains)
    or RemoteUrl has_any (ioc_domains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, host, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### Execution or drop of fake AI-platform installer (DeepSeek/Manus/Seedance/GPT-5.5/Kimi)

`UC_67_15` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.process_path) as path from datamodel=Endpoint.Processes where (Processes.process_name IN ("deepseek-v4-pro_x64.exe","deepseek-v4-flash_x64.exe","Manus_AI_Desktop_x64.exe","seedance_x64.exe","gpt-5.5-Pro_x64.exe","gpt-5.5-Thinking_x64.exe","Kimi-Swarm-Station_x64.exe") OR Processes.process_hash IN ("791efb555eefb7215e96659a1353a97416743b66bdd72705493129c64057d40e","c7c5072df9f83f4c440a5c3bb4be1d5f6c67bbf78f196406ca20d27b43b975b8","0a26238f6c516de5885457c93042531aa59bc206a9537cebf5267cedc6c68531","8610d4fb0ec5b525071c2aaec4df0f8fcbb3673aba58a7e1959fc44e83c0e2ca","99231deb373997364381d1eb513d2d42231d418c3a2db9007c5af9bd56ab9371","25270cc429ada8028b5b33220ed412c47907ecceea7377d608fac5af01bed56a","56d722b0331bf0aaa86bb37483486c6dff6ad9427fc473ed7c3226c21a9bdd23","5455341ed1bbe75a664fca2dd0794c508e1874f75360253a7ff5bc119bc92d80")) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let lure_binaries = dynamic(["deepseek-v4-pro_x64.exe","deepseek-v4-flash_x64.exe","Manus_AI_Desktop_x64.exe","seedance_x64.exe","gpt-5.5-Pro_x64.exe","gpt-5.5-Thinking_x64.exe","Kimi-Swarm-Station_x64.exe"]);
let ioc_sha256 = dynamic(["791efb555eefb7215e96659a1353a97416743b66bdd72705493129c64057d40e","c7c5072df9f83f4c440a5c3bb4be1d5f6c67bbf78f196406ca20d27b43b975b8","0a26238f6c516de5885457c93042531aa59bc206a9537cebf5267cedc6c68531","8610d4fb0ec5b525071c2aaec4df0f8fcbb3673aba58a7e1959fc44e83c0e2ca","99231deb373997364381d1eb513d2d42231d418c3a2db9007c5af9bd56ab9371","25270cc429ada8028b5b33220ed412c47907ecceea7377d608fac5af01bed56a","56d722b0331bf0aaa86bb37483486c6dff6ad9427fc473ed7c3226c21a9bdd23","5455341ed1bbe75a664fca2dd0794c508e1874f75360253a7ff5bc119bc92d80"]);
let ai_lure_regex = @"(?i)^(deepseek-v\d+(-pro|-flash)?|manus_ai_desktop|seedance|gpt-\d+(\.\d+)?-(pro|thinking)|kimi-swarm-station)_x64\.exe$";
union isfuzzy=false
    (DeviceProcessEvents
        | where Timestamp > ago(60d)
        | where FileName in~ (lure_binaries)
            or SHA256 in (ioc_sha256)
            or (FileName matches regex ai_lure_regex and FolderPath has_any (@"\Downloads\",@"\Temp\",@"\AppData\Local\Temp\",@"\Public\"))
        | project Timestamp, DeviceName, AccountName, EvtKind = "process", FileName, FolderPath, SHA256, ProcessCommandLine, ParentImage = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine),
    (DeviceFileEvents
        | where Timestamp > ago(60d)
        | where ActionType in ("FileCreated","FileRenamed")
        | where FileName in~ (lure_binaries) or SHA256 in (ioc_sha256)
        | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, EvtKind = "file", FileName, FolderPath, SHA256, ProcessCommandLine = InitiatingProcessCommandLine, ParentImage = InitiatingProcessFileName, ParentCmd = InitiatingProcessParentFileName)
| order by Timestamp desc
```

### Phishing redirect chain via awstrack.me / Rebrandly into AI-themed landing path

`UC_67_16` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls from datamodel=Web where (Web.url="*awstrack.me*" OR Web.url="*rebrand.ly*" OR Web.url="*rebrandly.com*" OR Web.url="*bitrix24.com*") (Web.url="*ChatGPT*" OR Web.url="*Claude*" OR Web.url="*Anthropic*" OR Web.url="*DeepSeek*" OR Web.url="*legendarytrendsbay*" OR Web.url="*awaydouble*") by Web.src, Web.user, Web.dest | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let phish_landings = dynamic(["legendarytrendsbay.shop","dash.awaydouble.org","awaydouble.org","servicing.pureplantcravings.com","pureplantcravings.com","brokeapt.com"]);
UrlClickEvents
| where Timestamp > ago(60d)
| where ActionType in ("ClickAllowed","ClickedThrough")
| where Url has_any (phish_landings)
    or UrlChain has_any (phish_landings)
    or (Url has_any ("awstrack.me","rebrand.ly","rebrandly.com","bitrix24.com") and Url matches regex @"(?i)(chatgpt|claude|anthropic|deepseek|manus|seedance|gpt-?5|kimi)")
    or Url matches regex @"(?i)https?://[^/]+/(ChatGPT|Claude|Anthropic|DeepSeek)/"
| project Timestamp, AccountUpn, NetworkMessageId, Url, UrlChain, ActionType, IsClickedThrough, IPAddress, Workload
| order by Timestamp desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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

### Microsoft Teams external-tenant chat from unverified IT-helpdesk impersonator

`UC_TEAMS_VISHING` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`o365_management_activity`
  Workload=MicrosoftTeams Operation=MessageSent
  ExternalParticipants=*
| where match(SenderDisplayName, "(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)")
| stats count, earliest(_time) as firstTime, latest(_time) as lastTime
    by SenderUpn, SenderDisplayName, RecipientUpn, ChatId
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Teams"
| where ActionType == "MessageSent"
| where RawEventData has "ExternalParticipants"
| extend SenderDisplayName = tostring(parse_json(RawEventData).SenderDisplayName)
| where SenderDisplayName matches regex @"(?i)(help.?desk|it.?support|service.?desk|tech.?support|admin)"
| project Timestamp, AccountDisplayName, IPAddress, ActivityType, SenderDisplayName, RawEventData
```

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — AI brands as bait: How threat actors are using the AI hype in social engineering

`UC_67_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — AI brands as bait: How threat actors are using the AI hype in social engineering ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("profluxeflowai-win-setup.exe","pythonw.exe","deepseek-v4-flash_x64.exe","tradeai.exe","deepseek-v4-pro_x64.exe","manus_ai_desktop_x64.exe","seedance_x64.exe","gpt-5.5-pro_x64.exe","gpt-5.5-thinking_x64.exe","kimi-swarm-station_x64.exe","fraudgpt_x64.exe","grokcli_x64.exe","gemma-4-omni_x64.exe","ltx-2.3_x64.exe","win-setup.exe") OR Processes.process_path="*\AppData\Local\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*\AppData\Local\*" OR Filesystem.file_name IN ("profluxeflowai-win-setup.exe","pythonw.exe","deepseek-v4-flash_x64.exe","tradeai.exe","deepseek-v4-pro_x64.exe","manus_ai_desktop_x64.exe","seedance_x64.exe","gpt-5.5-pro_x64.exe","gpt-5.5-thinking_x64.exe","kimi-swarm-station_x64.exe","fraudgpt_x64.exe","grokcli_x64.exe","gemma-4-omni_x64.exe","ltx-2.3_x64.exe","win-setup.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — AI brands as bait: How threat actors are using the AI hype in social engineering
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("profluxeflowai-win-setup.exe", "pythonw.exe", "deepseek-v4-flash_x64.exe", "tradeai.exe", "deepseek-v4-pro_x64.exe", "manus_ai_desktop_x64.exe", "seedance_x64.exe", "gpt-5.5-pro_x64.exe", "gpt-5.5-thinking_x64.exe", "kimi-swarm-station_x64.exe", "fraudgpt_x64.exe", "grokcli_x64.exe", "gemma-4-omni_x64.exe", "ltx-2.3_x64.exe", "win-setup.exe") or FolderPath has_any ("\AppData\Local\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("\AppData\Local\") or FileName in~ ("profluxeflowai-win-setup.exe", "pythonw.exe", "deepseek-v4-flash_x64.exe", "tradeai.exe", "deepseek-v4-pro_x64.exe", "manus_ai_desktop_x64.exe", "seedance_x64.exe", "gpt-5.5-pro_x64.exe", "gpt-5.5-thinking_x64.exe", "kimi-swarm-station_x64.exe", "fraudgpt_x64.exe", "grokcli_x64.exe", "gemma-4-omni_x64.exe", "ltx-2.3_x64.exe", "win-setup.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `legendarytrendsbay.shop`, `dash.awaydouble.org`, `awaydouble.org`, `servicing.pureplantcravings.com`, `pureplantcravings.com`, `brokeapt.com`, `pan.ssffaa19.xyz`, `ssffaa19.xyz` _(+2 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `791efb555eefb7215e96659a1353a97416743b66bdd72705493129c64057d40e`, `c7c5072df9f83f4c440a5c3bb4be1d5f6c67bbf78f196406ca20d27b43b975b8`, `0a26238f6c516de5885457c93042531aa59bc206a9537cebf5267cedc6c68531`, `8610d4fb0ec5b525071c2aaec4df0f8fcbb3673aba58a7e1959fc44e83c0e2ca`, `99231deb373997364381d1eb513d2d42231d418c3a2db9007c5af9bd56ab9371`, `25270cc429ada8028b5b33220ed412c47907ecceea7377d608fac5af01bed56a`, `56d722b0331bf0aaa86bb37483486c6dff6ad9427fc473ed7c3226c21a9bdd23`, `5455341ed1bbe75a664fca2dd0794c508e1874f75360253a7ff5bc119bc92d80` _(+6 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
