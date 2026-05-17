# [HIGH] Turla Turns Kazuar Backdoor Into Modular P2P Botnet for Persistent Access

**Source:** The Hacker News
**Published:** 2026-05-15
**Article:** https://thehackernews.com/2026/05/turla-turns-kazuar-backdoor-into.html

## Threat Profile

Turla Turns Kazuar Backdoor Into Modular P2P Botnet for Persistent Access 
 Ravie Lakshmanan  May 15, 2026 Botnet / Threat Intelligence 
The Russian state-sponsored hacking group known as
Turla 
has transformed its custom backdoor Kazuar into a modular peer-to-peer (P2P) botnet that's engineered for stealth and persistent access to compromised hosts.
Turla, per the U.S. Cybersecurity and Infrastructure Security Agency (CISA), is assessed to be affiliated with Center 16 of Russia's Federal Secu…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4`
- **SHA256:** `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9`
- **SHA256:** `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d`
- **SHA256:** `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1140** — Deobfuscate/Decode Files or Information
- **T1587.001** — Develop Capabilities: Malware
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1114.001** — Email Collection: Local Email Collection
- **T1119** — Automated Collection
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Turla Kazuar / Pelmeni / ShadowLoader Known SHA256 Execution

`UC_15_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
let kazuar_hashes = dynamic([
  "69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4",
  "c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9",
  "6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d",
  "436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85"
]);
union isfuzzy=true
(
  DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (kazuar_hashes) or InitiatingProcessSHA256 in (kazuar_hashes)
  | project Timestamp, DeviceName, AccountName, EventTable = "DeviceProcessEvents",
            FileName, FolderPath, SHA256, ProcessCommandLine,
            InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessCommandLine
),
(
  DeviceImageLoadEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (kazuar_hashes)
  | project Timestamp, DeviceName, EventTable = "DeviceImageLoadEvents",
            FileName, FolderPath, SHA256,
            InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessCommandLine
),
(
  DeviceFileEvents
  | where Timestamp > ago(30d)
  | where SHA256 in (kazuar_hashes)
  | project Timestamp, DeviceName, EventTable = "DeviceFileEvents",
            FileName, FolderPath, SHA256, ActionType,
            InitiatingProcessFileName, InitiatingProcessSHA256, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### [LLM] Kazuar Bridge C2: Exchange Web Services Calls from Non-Mail-Client .NET Binary

`UC_15_7` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/EWS/Exchange.asmx*" OR Web.url="*/ews/exchange.asmx*" OR Web.url="*/EWS/Services.wsdl*") AND NOT (Web.user_agent IN ("*Microsoft Office*","*Microsoft Outlook*","*Outlook*","*Thunderbird*","*Mozilla*","*Mac OS X Mail*","*Exchange Web Services*","*Teams*")) by Web.src Web.user Web.app Web.url Web.dest Web.user_agent Web.http_method
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT match(app,"(?i)outlook|excel|winword|powerpnt|onenote|teams|onedrive|msedge|chrome|firefox|brave|iexplore")
| sort - lastTime
```

**Defender KQL:**
```kql
let legit_ews_callers = dynamic([
  "outlook.exe","msoutlook.exe","onenote.exe","winword.exe","excel.exe",
  "powerpnt.exe","msaccess.exe","thunderbird.exe","msteams.exe","teams.exe",
  "ms-teams.exe","skype.exe","lync.exe","onedrive.exe","officeclicktorun.exe",
  "chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe",
  "powershell.exe","pwsh.exe","postman.exe","fiddler.exe",
  "backgroundtaskhost.exe","searchprotocolhost.exe"
]);
let legit_paths = dynamic([
  @"C:\Program Files\Microsoft Office\",
  @"C:\Program Files (x86)\Microsoft Office\",
  @"C:\Program Files\Common Files\Microsoft Shared\",
  @"C:\Program Files\WindowsApps\Microsoft.Teams",
  @"C:\Users\" 
]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("/ews/exchange.asmx","/EWS/Exchange.asmx","/ews/services.wsdl","/EWS/Services.wsdl")
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName !in~ (legit_ews_callers)
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files\Microsoft Office\")
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files (x86)\Microsoft Office\")
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files\Common Files\Microsoft Shared\")
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files\WindowsApps\Microsoft.Teams")
| extend IsDotNet = iif(InitiatingProcessVersionInfoProductName has_any (".NET","Microsoft .NET") or InitiatingProcessVersionInfoCompanyName has "Microsoft Corporation" and InitiatingProcessFileName !endswith ".exe", true, false)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256,
          InitiatingProcessVersionInfoCompanyName, InitiatingProcessVersionInfoProductName,
          RemoteUrl, RemoteIP, RemotePort, IsDotNet
| order by Timestamp desc
```

### [LLM] Kazuar Worker MAPI / Outlook Profile Harvesting from Non-Office Binary

`UC_15_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Microsoft\\Outlook\\*" OR Filesystem.file_name="*.ost" OR Filesystem.file_name="*.OST" OR Filesystem.file_name="*.pst" OR Filesystem.file_name="*.PST" OR Filesystem.file_name="*.nst") AND NOT Filesystem.process_name IN ("outlook.exe","OUTLOOK.EXE","winword.exe","excel.exe","powerpnt.exe","onenote.exe","searchindexer.exe","searchprotocolhost.exe","searchfilterhost.exe","explorer.exe","officeclicktorun.exe","backgroundtaskhost.exe","mssearch.exe") AND NOT Filesystem.process_path IN ("*\\Microsoft Office\\*","*\\Common Files\\Microsoft Shared\\*","*\\Windows\\System32\\*","*\\Windows\\SysWOW64\\*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.process_hash Filesystem.file_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
let office_binaries = dynamic([
  "outlook.exe","winword.exe","excel.exe","powerpnt.exe","msaccess.exe",
  "onenote.exe","mspub.exe","onedrive.exe","msteams.exe","teams.exe",
  "lync.exe","communicator.exe","skype.exe","wordpad.exe",
  "searchprotocolhost.exe","searchfilterhost.exe","searchindexer.exe",
  "mssearch.exe","officeclicktorun.exe","mso.exe","msosync.exe",
  "explorer.exe","backgroundtaskhost.exe","sense.exe","msmpeng.exe"
]);
union isfuzzy=true
(
  DeviceFileEvents
  | where Timestamp > ago(7d)
  | where ActionType in ("FileCreated","FileModified","FileRenamed")
  | where FolderPath has @"\Microsoft\Outlook\"
       or FileName endswith ".ost" or FileName endswith ".pst" or FileName endswith ".nst"
  | where InitiatingProcessAccountName !endswith "$"
  | where InitiatingProcessFileName !in~ (office_binaries)
  | where not(InitiatingProcessFolderPath startswith @"C:\Program Files\Microsoft Office\")
  | where not(InitiatingProcessFolderPath startswith @"C:\Program Files (x86)\Microsoft Office\")
  | where not(InitiatingProcessFolderPath startswith @"C:\Program Files\Common Files\Microsoft Shared\")
  | where not(InitiatingProcessFolderPath startswith @"C:\Windows\System32\")
  | where not(InitiatingProcessFolderPath startswith @"C:\Windows\SysWOW64\")
  | project Timestamp, DeviceName, InitiatingProcessAccountName,
            InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, InitiatingProcessSHA256,
            ActionType, FileName, FolderPath, EventTable = "DeviceFileEvents"
),
(
  DeviceImageLoadEvents
  | where Timestamp > ago(7d)
  | where FileName in~ ("olmapi32.dll","emsmdb32.dll","msmapi32.dll","mapir.dll","outlook.exe")
  | where InitiatingProcessAccountName !endswith "$"
  | where InitiatingProcessFileName !in~ (office_binaries)
  | where not(InitiatingProcessFolderPath startswith @"C:\Program Files\Microsoft Office\")
  | where not(InitiatingProcessFolderPath startswith @"C:\Program Files (x86)\Microsoft Office\")
  | where not(InitiatingProcessFolderPath startswith @"C:\Program Files\Common Files\Microsoft Shared\")
  | where not(InitiatingProcessFolderPath startswith @"C:\Windows\System32\")
  | where not(InitiatingProcessFolderPath startswith @"C:\Windows\SysWOW64\")
  | project Timestamp, DeviceName, InitiatingProcessAccountName,
            InitiatingProcessFileName, InitiatingProcessFolderPath,
            InitiatingProcessCommandLine, InitiatingProcessSHA256,
            FileName, FolderPath, EventTable = "DeviceImageLoadEvents"
)
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4`, `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9`, `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d`, `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
