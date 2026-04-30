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
- **T1566.002** — Phishing: Spearphishing Link
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1620** — Reflective Code Loading
- **T1027.011** — Fileless Storage
- **T1614.001** — System Location Discovery: System Language Discovery
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1027.013** — Obfuscated Files or Information: Encrypted/Encoded File
- **T1055.012** — Process Injection: Process Hollowing
- **T1140** — Deobfuscate/Decode Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Maverick banker: WhatsApp-Web-delivered LNK launching fileless PowerShell/.NET chain

`UC_137_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_path="*\\Downloads\\*" OR Filesystem.file_path="*\\WhatsApp*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\*") AND (Filesystem.file_name="*.lnk" OR Filesystem.file_name="*.zip") AND (Filesystem.process_name IN ("chrome.exe","msedge.exe","brave.exe","firefox.exe","WhatsApp.exe","Whatsapp.exe")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | rename file_name as drop_file, file_path as drop_path | join type=inner dest [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.parent_process_name="explorer.exe" AND Processes.process_name IN ("powershell.exe","pwsh.exe","conhost.exe") AND (Processes.process="*-nop*" OR Processes.process="*-w*hidden*" OR Processes.process="*-WindowStyle*Hidden*" OR Processes.process="*FromBase64String*" OR Processes.process="*Reflection.Assembly*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*[Activator]::CreateInstance*" OR Processes.process="*GetCurrentTimeZone*" OR Processes.process="*pt-BR*" OR Processes.process="*E. South America Standard Time*") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` ] | where firstTime>0 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let dropWindow = 30m;
let whatsappDrop = DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed")
| where FolderPath has_any (@"\Downloads\", @"\WhatsApp", @"\AppData\Local\Temp\")
| where FileName endswith ".lnk" or FileName endswith ".zip"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","brave.exe","firefox.exe","whatsapp.exe")
| project DropTime=Timestamp, DeviceId, DeviceName, DroppedFile=FileName, DropPath=FolderPath, DropParent=InitiatingProcessFileName;
let filelessChain = DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("-nop","-w hidden","-WindowStyle Hidden","FromBase64String","Reflection.Assembly","Invoke-Expression","[Activator]::CreateInstance","GetCurrentTimeZone","E. South America Standard Time","pt-BR","DonutLoader")
| project ExecTime=Timestamp, DeviceId, ProcessCommandLine, InitiatingProcessCommandLine;
whatsappDrop
| join kind=inner filelessChain on DeviceId
| where ExecTime between (DropTime .. DropTime + dropWindow)
| project DropTime, ExecTime, DeviceName, DroppedFile, DropPath, DropParent, ProcessCommandLine, InitiatingProcessCommandLine
```

### [LLM] Pure family (PureCrypter/PureRAT) delivered via accounting-themed attachments targeting EDM/invoice fraud

`UC_137_6` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path values(Filesystem.process_name) as drop_proc from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_path="*\\Content.Outlook\\*" OR Filesystem.file_path="*\\Downloads\\*" OR Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*\\AppData\\Roaming\\*") AND (Filesystem.file_name="*fatura*" OR Filesystem.file_name="*boleto*" OR Filesystem.file_name="*nfe*" OR Filesystem.file_name="*nota_fiscal*" OR Filesystem.file_name="*nota-fiscal*" OR Filesystem.file_name="*invoice*" OR Filesystem.file_name="*recibo*" OR Filesystem.file_name="*comprovante*" OR Filesystem.file_name="*orcamento*" OR Filesystem.file_name="*orçamento*" OR Filesystem.file_name="*contrato*" OR Filesystem.file_name="*pedido*" OR Filesystem.file_name="*NF-e*") AND (Filesystem.file_name="*.exe" OR Filesystem.file_name="*.scr" OR Filesystem.file_name="*.lnk" OR Filesystem.file_name="*.iso" OR Filesystem.file_name="*.img" OR Filesystem.file_name="*.zip" OR Filesystem.file_name="*.rar" OR Filesystem.file_name="*.7z") by Filesystem.dest Filesystem.user | `drop_dm_object_name(Filesystem)` | join type=inner dest user [ | tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("OUTLOOK.EXE","outlook.exe","thunderbird.exe","winrar.exe","7zg.exe","7zfm.exe","explorer.exe")) AND (Processes.process_name="*.exe" OR Processes.process_name="*.scr") AND (Processes.process="*MSBuild.exe*" OR Processes.process="*RegAsm.exe*" OR Processes.process="*InstallUtil.exe*" OR Processes.process="*aspnet_compiler.exe*" OR Processes.process="*csc.exe*" OR Processes.original_file_name="*PureCrypter*" OR Processes.process_name="PureCrypter*") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` ] | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let lure = DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FolderPath has_any (@"\Content.Outlook\", @"\Downloads\", @"\AppData\Local\Temp\", @"\AppData\Roaming\")
| where FileName matches regex @"(?i)(fatura|boleto|nf-?e|nota[ _-]?fiscal|invoice|recibo|comprovante|or[cç]amento|contrato|pedido|cobran[cç]a)"
| where FileName endswith_cs ".exe" or FileName endswith_cs ".scr" or FileName endswith_cs ".lnk" or FileName endswith_cs ".iso" or FileName endswith_cs ".img" or FileName endswith_cs ".zip" or FileName endswith_cs ".rar" or FileName endswith_cs ".7z"
| project DropTime=Timestamp, DeviceId, DeviceName, AccountName, DroppedFile=FileName, DropPath=FolderPath, DropParent=InitiatingProcessFileName, DropSHA256=SHA256;
let pureExec = DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("outlook.exe","thunderbird.exe","winrar.exe","7zg.exe","7zfm.exe","explorer.exe")
      or ProcessVersionInfoOriginalFileName has "PureCrypter"
| where (FileName endswith ".exe" or FileName endswith ".scr")
      or ProcessCommandLine has_any ("MSBuild.exe","RegAsm.exe","InstallUtil.exe","aspnet_compiler.exe","csc.exe","jsc.exe")
      or ProcessVersionInfoOriginalFileName has_any ("PureCrypter","PureRAT","PureLogs","PureHVNC")
| project ExecTime=Timestamp, DeviceId, ProcName=FileName, ProcCmd=ProcessCommandLine, ProcParent=InitiatingProcessFileName, ProcSHA256=SHA256, OriginalFileName=ProcessVersionInfoOriginalFileName;
lure
| join kind=inner pureExec on DeviceId
| where ExecTime between (DropTime .. DropTime + 1h)
| project DropTime, ExecTime, DeviceName, AccountName, DroppedFile, DropPath, DropParent, ProcName, ProcCmd, OriginalFileName, DropSHA256, ProcSHA256
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
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe")
| where ProcessCommandLine matches regex @"(?i)(iex|invoke-expression|frombase64|downloadstring|hxxp|curl |wget )"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: 7 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
