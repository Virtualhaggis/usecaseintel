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
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567.003** — Exfiltration Over Web Service: Exfiltration to Text Storage Sites
- **T1048.003** — Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol
- **T1071.003** — Application Layer Protocol: Mail Protocols
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1555** — Credentials from Password Stores
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SnakeStealer Telegram Bot Exfiltration via api.telegram.org from Non-Telegram Process

`UC_362_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.http_method) as method values(Web.dest) as dest from datamodel=Web where Web.url="*api.telegram.org/bot*" AND NOT Web.process IN ("telegram.exe","Telegram.exe","TelegramDesktop.exe","Updater.exe") by Web.src Web.user Web.process Web.dest | `drop_dm_object_name(Web)` | rename firstTime as _time | convert ctime(_time) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "api.telegram.org"
| where InitiatingProcessFileName !in~ ("telegram.exe","updater.exe")
| where InitiatingProcessFolderPath !contains @"\Telegram Desktop\"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName,
          AccountUpn=InitiatingProcessAccountUpn,
          ProcessName=InitiatingProcessFileName,
          ProcessPath=InitiatingProcessFolderPath,
          ProcessCmd=InitiatingProcessCommandLine,
          ProcessSHA256=InitiatingProcessSHA256,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] SnakeStealer SMTP Credential Exfiltration to Public Webmail Relays from Non-Mail Client

`UC_362_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.process) as process values(All_Traffic.user) as user from datamodel=Network_Traffic where All_Traffic.dest_port IN (587,465,25) AND All_Traffic.dest IN ("smtp.zoho.com","smtp.gmail.com","smtp-mail.outlook.com","smtp.mail.yahoo.com","smtp.yandex.com","smtp.mail.ru","mail.privateemail.com") AND NOT All_Traffic.process IN ("outlook.exe","thunderbird.exe","emclient.exe","mailbird.exe","msimn.exe","HostedOffice.exe") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process | `drop_dm_object_name(All_Traffic)` | rename firstTime as _time | convert ctime(_time) ctime(lastTime)
```

**Defender KQL:**
```kql
let SmtpHosts = dynamic(["smtp.zoho.com","smtp.gmail.com","smtp-mail.outlook.com","smtp.mail.yahoo.com","smtp.yandex.com","smtp.mail.ru","mail.privateemail.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (587, 465, 25)
| where RemoteUrl has_any (SmtpHosts)
| where InitiatingProcessFileName !in~ ("outlook.exe","thunderbird.exe","emclient.exe","mailbird.exe","msimn.exe","hostedoffice.exe")
| where InitiatingProcessFolderPath !contains @"\Microsoft Office\"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName,
          AccountUpn=InitiatingProcessAccountUpn,
          ProcessName=InitiatingProcessFileName,
          ProcessPath=InitiatingProcessFolderPath,
          ProcessCmd=InitiatingProcessCommandLine,
          ProcessSHA256=InitiatingProcessSHA256,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] SnakeStealer Startup-Folder Persistence (ageless.vbs / .exe drop in Programs\Startup)

`UC_362_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.user) as user values(Filesystem.process_name) as process values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where Filesystem.action=created AND Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" AND (Filesystem.file_name="*.vbs" OR Filesystem.file_name="*.js" OR Filesystem.file_name="*.lnk" OR Filesystem.file_name="*.exe" OR Filesystem.file_name="*.bat" OR Filesystem.file_name="*.cmd" OR Filesystem.file_name="*.wsf" OR Filesystem.file_name="*.hta") AND NOT Filesystem.process_name IN ("explorer.exe","setup.exe","msiexec.exe","TrustedInstaller.exe","OfficeClickToRun.exe","OneDriveSetup.exe") by host Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | rename firstTime as _time | convert ctime(_time) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has @"\Microsoft\Windows\Start Menu\Programs\Startup\"
| where FileName endswith ".vbs" or FileName endswith ".js"
       or FileName endswith ".lnk" or FileName endswith ".exe"
       or FileName endswith ".bat" or FileName endswith ".cmd"
       or FileName endswith ".wsf" or FileName endswith ".hta"
| where InitiatingProcessFileName !in~ ("explorer.exe","msiexec.exe","setup.exe","TrustedInstaller.exe","OfficeClickToRun.exe","OneDriveSetup.exe","Update.exe")
| where InitiatingProcessFolderPath !startswith @"C:\Program Files"
| where InitiatingProcessFolderPath !startswith @"C:\Windows\System32\"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName,
          AccountUpn=InitiatingProcessAccountUpn,
          FileName, FolderPath, SHA256,
          DropperFile=InitiatingProcessFileName,
          DropperPath=InitiatingProcessFolderPath,
          DropperCmd=InitiatingProcessCommandLine,
          DropperSHA256=InitiatingProcessSHA256,
          DropperCompany=InitiatingProcessVersionInfoCompanyName
| order by Timestamp desc
```

### [LLM] SnakeStealer Wi-Fi Credential Harvest via netsh wlan show profile key=clear

`UC_362_7` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process) as parent_cmd values(Processes.parent_process_name) as parent_name values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name="netsh.exe" AND Processes.process="*wlan*" AND Processes.process="*key=clear*" AND NOT Processes.parent_process_name IN ("mmc.exe","wininit.exe","services.exe","SCNotification.exe") by host Processes.user Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | rename firstTime as _time | convert ctime(_time) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "netsh.exe"
| where ProcessCommandLine has "wlan"
| where ProcessCommandLine has "key=clear" or ProcessCommandLine has "key = clear"
| where InitiatingProcessFileName !in~ ("mmc.exe","wininit.exe","services.exe","SCNotification.exe")
| where AccountName !endswith "$"
| extend ParentInUserWriteable = (InitiatingProcessFolderPath has @"\AppData\Local\Temp\"
                                  or InitiatingProcessFolderPath has @"\AppData\Roaming\"
                                  or InitiatingProcessFolderPath has @"\Users\Public\"
                                  or InitiatingProcessFolderPath has @"\ProgramData\")
| project Timestamp, DeviceName, AccountName, AccountUpn,
          ChildCmd=ProcessCommandLine,
          ParentName=InitiatingProcessFileName,
          ParentPath=InitiatingProcessFolderPath,
          ParentCmd=InitiatingProcessCommandLine,
          ParentSHA256=InitiatingProcessSHA256,
          ParentCompany=InitiatingProcessVersionInfoCompanyName,
          ParentInUserWriteable
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


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
