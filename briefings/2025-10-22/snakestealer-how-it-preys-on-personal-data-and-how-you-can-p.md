# [CRIT] SnakeStealer: How it preys on personal data – and how you can protect yourself

**Source:** ESET WeLiveSecurity
**Published:** 2025-10-22
**Article:** https://www.welivesecurity.com/en/malware/snakestealer-personal-data-stay-safe/

## Threat Profile

Infostealers remain one of the most persistent threats on today’s threat landscape. They’re built to quietly siphon off valuable information , typically login credentials and financial and cryptocurrency details, from compromised systems and send it to adversaries. And they do so with great success.
ESET researchers have tracked numerous campaigns recently where an infostealer was the final payload. Agent Tesla, Lumma Stealer, FormBook and HoudRAT continue to make the rounds in large numbers, bu…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

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
- **T1567.002** — Exfiltration to Cloud Storage
- **T1102** — Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1547.001** — Registry Run Keys / Startup Folder
- **T1113** — Screen Capture
- **T1564.001** — Hidden Files and Directories
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1218.009** — System Binary Proxy Execution: Regsvcs/Regasm

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SnakeStealer Telegram bot C2 — api.telegram.org/bot<token>/send* from non-browser process

`UC_307_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user from datamodel=Web where Web.url="*api.telegram.org/bot*" (Web.url="*sendMessage*" OR Web.url="*sendDocument*" OR Web.url="*sendPhoto*" OR Web.url="*getUpdates*") by Web.dest Web.src Web.process_name Web.url | `drop_dm_object_name(Web)` | where NOT match(process_name,"(?i)Telegram\.exe|telegram-desktop") AND NOT match(process_name,"(?i)chrome\.exe|firefox\.exe|msedge\.exe|brave\.exe|opera\.exe") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let suspicious_procs = DeviceProcessEvents | where FolderPath has_any (@"\AppData\Roaming\", @"\AppData\Local\Temp\", @"\Users\Public\") or ProcessVersionInfoOriginalFileName has "RegSvcs.exe" or ProcessVersionInfoOriginalFileName has "RegAsm.exe" or ProcessVersionInfoOriginalFileName has "InstallUtil.exe" | distinct DeviceId, InitiatingProcessId=ProcessId, InitiatingProcessFileName=FileName, InitiatingProcessFolderPath=FolderPath; DeviceNetworkEvents | where RemoteUrl has "api.telegram.org/bot" and (RemoteUrl has_any ("sendMessage","sendDocument","sendPhoto","getUpdates")) | where InitiatingProcessFileName !in~ ("Telegram.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe") | join kind=leftouter suspicious_procs on DeviceId, $left.InitiatingProcessId == $right.InitiatingProcessId | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, ActionType
```

### [LLM] SnakeStealer on-disk artefacts — ageless.vbs in Startup, Documents\SnakeKeylogger screenshots, AppData\Roaming copy

`UC_307_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\ageless.vbs" OR Filesystem.file_path="*\\Documents\\SnakeKeylogger\\Screenshot*.jpg" OR Filesystem.file_path="*\\Documents\\SnakeKeylogger\\*\\Screenshot*.jpg") by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents | where (FolderPath endswith @"\Microsoft\Windows\Start Menu\Programs\Startup" and FileName =~ "ageless.vbs") or (FolderPath has @"\Documents\SnakeKeylogger" and FileName matches regex @"(?i)Screenshot.*\.jpg") or (FolderPath has @"SnakeKeylogger" and FileName endswith ".log") | project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName | sort by Timestamp desc
```

### [LLM] SnakeStealer SMTP/FTP credential exfiltration from .NET binary in user profile

`UC_307_6` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (21,25,465,587) AND (All_Traffic.process_name IN ("RegSvcs.exe","RegAsm.exe","InstallUtil.exe","MSBuild.exe","aspnet_compiler.exe") OR All_Traffic.process_path="*\\AppData\\Roaming\\*" OR All_Traffic.process_path="*\\AppData\\Local\\Temp\\*" OR All_Traffic.process_path="*\\ProgramData\\*") by All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.process_path | `drop_dm_object_name(All_Traffic)` | where dest_port!="" | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let dotnet_hosts = dynamic(["regsvcs.exe","regasm.exe","installutil.exe","msbuild.exe","aspnet_compiler.exe"]); DeviceNetworkEvents | where RemotePort in (21, 25, 465, 587) | where InitiatingProcessFileName in~ (dotnet_hosts) or InitiatingProcessFolderPath has_any (@"\AppData\Roaming\", @"\AppData\Local\Temp\", @"\ProgramData\") | summarize ConnCount=count(), Ports=make_set(RemotePort), Dests=make_set(RemoteIP), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName | where ConnCount > 0 | order by LastSeen desc
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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe","mspub.exe","visio.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: 7 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
