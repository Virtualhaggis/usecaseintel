# [CRIT] Operation MacroMaze: new APT28  campaign using basic tooling and legit infrastructure

**Source:** Lab52
**Published:** 2026-02-13
**Article:** https://lab52.io/blog/operation-macromaze-new-apt28-campaign-using-basic-tooling-and-legit-infrastructure/

## Threat Profile

Overview 
LAB52 has been monitoring a campaign dubbed “Operation MacroMaze”, which, based on its characteristics, can be attributed to APT28, also known as Fancy Bear, Forest Blizzard or FROZENLAKE. The campaign has been active at least since late September 2025 through January 2026, targeting specific entities in Western and Central Europe. The campaign relies on basic tooling and in the exploitation of legitimate services for infrastructure and data exfiltration .
Multiple documents associated…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `webhook.site`
- **SHA256:** `b0f9f0a34ccab1337fbcca24b4f894de8d6d3a6f5db2e0463e2320215e4262e4`
- **SHA256:** `c3b617e0c6b8f01cf628a2b3db40e8d06ef20a3c71365ccc1799787119246010`
- **SHA256:** `df60fa6008b1a0b79c394b42d3ada6bab18b798f3c2ca1530a3e0cb4fbbbe9f6`
- **SHA256:** `58cfb8b9fee1caa94813c259901dc1baa96bae7d30d79b79a7d441d0ee4e577e`
- **SHA256:** `9097d9cf5e6659e869bf2edf766741b687e3d8570036d853c0ca59ae72f9e9fc`
- **SHA256:** `5486107244ecaa3a0824895fa432827cc12df69620ca94aaa4ad75f39ac79588`
- **SHA256:** `ed8f20bbab18b39a67e4db9a03090e5af8dc8ec24fe1ddf3521b3f340a8318c1`

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
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1564.003** — Hide Artifacts: Hidden Window
- **T1102** — Web Service
- **T1567** — Exfiltration Over Web Service
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1567.002** — Exfiltration to Cloud Storage / Web Service
- **T1221** — Template Injection

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] APT28 MacroMaze: Edge launched off-screen or headless to webhook.site by non-browser parent

`UC_417_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_process values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="msedge.exe" Processes.parent_process_name IN ("cmd.exe","wscript.exe","cscript.exe") (Processes.process="*--window-position=10000,10000*" OR Processes.process="*--window-size=1,1*" OR Processes.process="*--headless=new*" OR (Processes.process="*--ignore-certificate-errors*" AND Processes.process="*webhook*")) by Processes.dest Processes.user Processes.process Processes.parent_process Processes.process_id | `drop_dm_object_name(Processes)` | where match(process,"(?i)webhook\.site|--window-position=10000,10000|--headless=new")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "msedge.exe"
| where InitiatingProcessFileName in~ ("cmd.exe","wscript.exe","cscript.exe")
| where AccountName !endswith "$"
| where ProcessCommandLine has_any ("--window-position=10000,10000","--window-size=1,1","--headless=new","--ignore-certificate-errors")
   or ProcessCommandLine has "webhook.site"
| where ProcessCommandLine has "webhook.site"
   or InitiatingProcessFolderPath has_any (@"\Users\", @"\AppData\", @"\Downloads\")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ParentPath = InitiatingProcessFolderPath,
          ChildCmd = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] APT28 MacroMaze: schtasks creating wscript-launched persistence with 20/30/61-minute repeat

`UC_417_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" (Processes.process="*/create*" OR Processes.process="*/xml*") Processes.process="*wscript*" by Processes.dest Processes.user Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where match(process,"(?i)\\\\Users\\\\[^\\\\]+\\\\.*\\.vbs") OR match(process,"(?i)\\.bat") | rename process as command | table firstTime lastTime dest user parent command
```

**Defender KQL:**
```kql
// Direct schtasks creation observed by MacroMaze CMD
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any ("/create","/xml")
| where ProcessCommandLine has "wscript"
| where ProcessCommandLine has_any (@"\Users\", "%USERPROFILE%", @"\AppData\")
| where ProcessCommandLine matches regex @"(?i)\.(bat|cmd)\b"
| extend SuspiciousInterval = iff(ProcessCommandLine has_any ("PT20M","PT30M","PT61M","/RI 20","/RI 30","/RI 61"), true, false)
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildCmd = ProcessCommandLine,
          SuspiciousInterval
| order by Timestamp desc
```

### [LLM] APT28 MacroMaze: Office or Edge HTTP traffic to webhook.site (INCLUDEPICTURE tracker + exfil)

`UC_417_12` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user) as user values(Web.dest) as dest from datamodel=Web where Web.url="*webhook.site*" Web.process_name IN ("winword.exe","excel.exe","powerpnt.exe","msedge.exe","wscript.exe","cscript.exe","cmd.exe") by Web.src Web.process_name Web.http_method Web.url | `drop_dm_object_name(Web)` | eval indicator=case(match(urls,"(?i)docopened\.jpg"),"INCLUDEPICTURE_tracker", http_method="POST","Possible_exfil_POST", true(),"Other_webhook_traffic") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has "webhook.site" or RemoteUrl endswith ".webhook.site"
| where InitiatingProcessFileName in~ (
    "winword.exe","excel.exe","powerpnt.exe",
    "msedge.exe","wscript.exe","cscript.exe","cmd.exe")
| extend Indicator = case(
    RemoteUrl has "docopened.jpg", "INCLUDEPICTURE_tracker",
    InitiatingProcessFileName =~ "winword.exe", "Office_to_webhook.site",
    InitiatingProcessFileName =~ "msedge.exe", "Edge_exfil_or_payload",
    "Script_host_to_webhook.site")
| project Timestamp, DeviceName,
          Account = InitiatingProcessAccountName,
          Process = InitiatingProcessFileName,
          ProcessCmd = InitiatingProcessCommandLine,
          RemoteIP, RemotePort, RemoteUrl, Indicator
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

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### Article-specific behavioural hunt — Operation MacroMaze: new APT28  campaign using basic tooling and legit infrastru

`UC_417_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Operation MacroMaze: new APT28  campaign using basic tooling and legit infrastru ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("4zjwj81sp.exe","6p8wwn4ja.exe") OR Processes.process_path="*C:\Windows\4zjwj81sp.exe*" OR Processes.process_path="*C:\Users\user\Desktop\Informatii.doc*" OR Processes.process_path="*C:\Users\user\Desktop\attachment.docm*" OR Processes.process_path="*C:\Windows\6p8wwn4ja.exe*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*C:\Windows\4zjwj81sp.exe*" OR Filesystem.file_path="*C:\Users\user\Desktop\Informatii.doc*" OR Filesystem.file_path="*C:\Users\user\Desktop\attachment.docm*" OR Filesystem.file_path="*C:\Windows\6p8wwn4ja.exe*" OR Filesystem.file_name IN ("4zjwj81sp.exe","6p8wwn4ja.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Operation MacroMaze: new APT28  campaign using basic tooling and legit infrastru
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("4zjwj81sp.exe", "6p8wwn4ja.exe") or FolderPath has_any ("C:\Windows\4zjwj81sp.exe", "C:\Users\user\Desktop\Informatii.doc", "C:\Users\user\Desktop\attachment.docm", "C:\Windows\6p8wwn4ja.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("C:\Windows\4zjwj81sp.exe", "C:\Users\user\Desktop\Informatii.doc", "C:\Users\user\Desktop\attachment.docm", "C:\Windows\6p8wwn4ja.exe") or FileName in~ ("4zjwj81sp.exe", "6p8wwn4ja.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `webhook.site`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `b0f9f0a34ccab1337fbcca24b4f894de8d6d3a6f5db2e0463e2320215e4262e4`, `c3b617e0c6b8f01cf628a2b3db40e8d06ef20a3c71365ccc1799787119246010`, `df60fa6008b1a0b79c394b42d3ada6bab18b798f3c2ca1530a3e0cb4fbbbe9f6`, `58cfb8b9fee1caa94813c259901dc1baa96bae7d30d79b79a7d441d0ee4e577e`, `9097d9cf5e6659e869bf2edf766741b687e3d8570036d853c0ca59ae72f9e9fc`, `5486107244ecaa3a0824895fa432827cc12df69620ca94aaa4ad75f39ac79588`, `ed8f20bbab18b39a67e4db9a03090e5af8dc8ec24fe1ddf3521b3f340a8318c1`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
