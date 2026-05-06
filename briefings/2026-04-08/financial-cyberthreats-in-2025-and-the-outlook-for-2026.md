# [CRIT] Financial cyberthreats in 2025 and the outlook for 2026

**Source:** Securelist (Kaspersky)
**Published:** 2026-04-08
**Article:** https://securelist.com/financial-threat-report-2025/119304/

## Threat Profile

Table of Contents
Key findings 
Financial phishing 
Online shopping scams 
Payment system phishing 
Financial malware 
Financial cyberthreats on the dark web 
Compromised accounts 
Compromised payment cards 
Data breaches 
Sale of bank accounts and payment cards 
Compiled databases 
Creation of phishing websites 
Conclusion 
Authors
Olga Altukhova 
Oleg Kupreev 
Polina Tretyak 
In 2025, the financial cyberthreat landscape continued to evolve. While traditional PC banking malware declined in rela…

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1027** — Obfuscated Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1185** — Browser Session Hijacking

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Maverick banker — WhatsApp Desktop drops LNK/ZIP followed by fileless PowerShell IEX execution

`UC_149_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as drop_time from datamodel=Endpoint.Filesystem where Filesystem.process_name="WhatsApp.exe" AND (Filesystem.file_name="*.zip" OR Filesystem.file_name="*.lnk" OR Filesystem.file_name="*.bat" OR Filesystem.file_name="*.cmd" OR Filesystem.file_name="*.vbs" OR Filesystem.file_name="*.js" OR Filesystem.file_name="*.hta") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| join type=inner dest user [
    | tstats summariesonly=t count min(_time) as exec_time values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe") AND (Processes.process="*IEX*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*DownloadString*" OR Processes.process="*Net.WebClient*" OR Processes.process="*FromBase64String*" OR Processes.process="*-enc *" OR Processes.process="*-EncodedCommand*" OR Processes.process="*WPPConnect*") by Processes.dest Processes.user Processes.process_name
    | `drop_dm_object_name(Processes)`
  ]
| eval delay_sec = exec_time - drop_time
| where delay_sec >= 0 AND delay_sec <= 900
| table drop_time exec_time delay_sec dest user file_path file_name process_name cmdlines
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSec = 900;
let WhatsAppDrops = DeviceFileEvents
    | where Timestamp > ago(LookbackDays)
    | where InitiatingProcessFileName =~ "WhatsApp.exe"
    | where ActionType in ("FileCreated","FileRenamed","FileModified")
    | where FileName endswith ".zip" or FileName endswith ".lnk"
        or FileName endswith ".bat" or FileName endswith ".cmd"
        or FileName endswith ".vbs" or FileName endswith ".js"
        or FileName endswith ".hta" or FileName endswith ".rar"
    | project DropTime = Timestamp, DeviceId, DeviceName,
              DropName = FileName, DropPath = FolderPath,
              InitiatingProcessAccountName;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
| where ProcessCommandLine has_any ("IEX","Invoke-Expression","DownloadString","FromBase64String","Net.WebClient","DownloadFile","-enc ","-EncodedCommand","WPPConnect")
| join kind=inner WhatsAppDrops on DeviceId
| where Timestamp between (DropTime .. DropTime + WindowSec * 1s)
| project DropTime, ExecTime = Timestamp, DeviceName, AccountName,
          DropName, DropPath, ChildBin = FileName,
          ChildCmd = ProcessCommandLine,
          ParentBin = InitiatingProcessFileName,
          DelaySec = datetime_diff('second', Timestamp, DropTime)
| order by DropTime desc
```

### [LLM] Maverick WPPConnect self-propagation — WhatsApp Web traffic from non-browser process

`UC_149_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ips values(All_Traffic.dest_port) as dest_ports from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host IN ("web.whatsapp.com","static.whatsapp.net","*.whatsapp.net") OR All_Traffic.url IN ("*web.whatsapp.com*","*wppconnect*")) AND All_Traffic.process_name!="chrome.exe" AND All_Traffic.process_name!="msedge.exe" AND All_Traffic.process_name!="firefox.exe" AND All_Traffic.process_name!="brave.exe" AND All_Traffic.process_name!="opera.exe" AND All_Traffic.process_name!="iexplore.exe" AND All_Traffic.process_name!="arc.exe" AND All_Traffic.process_name!="vivaldi.exe" AND All_Traffic.process_name!="WhatsApp.exe" AND All_Traffic.process_name!="Whatsapp.exe" by All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.process_id All_Traffic.dest_host
| `drop_dm_object_name(All_Traffic)`
| where isnotnull(process_name)
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let Browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","arc.exe","vivaldi.exe","WhatsApp.exe","Whatsapp.exe","electron.exe"]);
let WaUrls = dynamic(["web.whatsapp.com","static.whatsapp.net","wppconnect"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (WaUrls)
| where InitiatingProcessFileName !in~ (Browsers)
| where InitiatingProcessAccountName !endswith "$"
| where RemoteIPType == "Public"
| summarize ConnCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            DistinctMinutes = dcount(bin(Timestamp, 1m)),
            SampleCmd = any(InitiatingProcessCommandLine),
            SampleHash = any(InitiatingProcessSHA256),
            ParentBin = any(InitiatingProcessParentFileName)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl
| where ConnCount >= 3 or DistinctMinutes >= 2
| order by FirstSeen desc
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


## Why this matters

Severity classified as **CRIT** based on: 7 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
