# [CRIT] Attackers Abuse CAPTCHA and ClickFix Tactics to Boost Credential Theft Campaigns

**Source:** Cyber Security News
**Published:** 2026-05-01
**Article:** https://cybersecuritynews.com/attackers-abuse-captcha-and-clickfix-tactics/

## Threat Profile

Home Cyber Security News 
Attackers Abuse CAPTCHA and ClickFix Tactics to Boost Credential Theft Campaigns 
By Tushar Subhra Dutta 
May 1, 2026 
Cybercriminals are no longer relying on simple email tricks alone. Across the first quarter of 2026, attackers have been sharpening their approach by using CAPTCHA pages and ClickFix techniques to supercharge credential theft operations at an alarming scale. 
During Q1 2026, Microsoft Threat Intelligence tracked approximately 8.3 billion email-based phi…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1027.009** — Obfuscated Files or Information: Embedded Payloads
- **T1557** — Adversary-in-the-Middle
- **T1539** — Steal Web Session Cookie

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ClickFix CAPTCHA execution: RunMRU populated with LOLBin command followed by explorer-spawned exec

`UC_15_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen from datamodel=Endpoint.Registry where Registry.registry_path="*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU*" (Registry.registry_value_data="*powershell*" OR Registry.registry_value_data="*mshta*" OR Registry.registry_value_data="*curl*" OR Registry.registry_value_data="*iwr *" OR Registry.registry_value_data="*iex *" OR Registry.registry_value_data="*Invoke-WebRequest*" OR Registry.registry_value_data="*Invoke-Expression*" OR Registry.registry_value_data="*FromBase64String*" OR Registry.registry_value_data="*-w hidden*" OR Registry.registry_value_data="*-nop*" OR Registry.registry_value_data="*msiexec*" OR Registry.registry_value_data="*certutil*" OR Registry.registry_value_data="*\\\\*@SSL*" OR Registry.registry_value_data="*webdav*" OR Registry.registry_value_data="*net use*") by Registry.dest Registry.user Registry.registry_value_data
| `drop_dm_object_name(Registry)`
| join type=inner dest [ | tstats `summariesonly` count values(Processes.process) as cmdline values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.parent_process_name="explorer.exe" Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe","cscript.exe","curl.exe","msiexec.exe","certutil.exe","rundll32.exe") by Processes.dest Processes.user _time | `drop_dm_object_name(Processes)` | rename _time as execTime ]
| where execTime>=firstSeen AND execTime<=firstSeen+300
| table firstSeen execTime dest user registry_value_data process_name cmdline
```

**Defender KQL:**
```kql
let RunMRUWrites = DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType == "RegistryValueSet"
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where RegistryValueData has_any ("powershell","mshta"," curl "," iwr "," iex ","Invoke-WebRequest","Invoke-Expression","FromBase64String","-w hidden","-nop","msiexec","certutil","webdav","net use \\\\")
| project RegTime=Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, RegistryValueData;
let RunBoxExec = DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe","cscript.exe","curl.exe","msiexec.exe","certutil.exe","rundll32.exe")
| project ExecTime=Timestamp, DeviceId, AccountName, FileName, ProcessCommandLine;
RunMRUWrites
| join kind=inner RunBoxExec on DeviceId
| where ExecTime between (RegTime .. RegTime + 5m)
| project RegTime, ExecTime, DeviceName, AccountName=InitiatingProcessAccountName, RegistryValueData, FileName, ProcessCommandLine
```

### [LLM] SVG email attachment opened in browser from Outlook temp dir then beacons to external CAPTCHA host

`UC_15_8` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen from datamodel=Endpoint.Processes where Processes.process_name IN ("msedge.exe","chrome.exe","firefox.exe","brave.exe","iexplore.exe") (Processes.process="*.svg*") (Processes.process="*\\INetCache\\Content.Outlook\\*" OR Processes.process="*\\AppData\\Local\\Microsoft\\Olk\\Attachments\\*" OR Processes.process="*\\AppData\\Local\\Temp\\*" OR Processes.process="*\\Downloads\\*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| rename process as svg_cmdline
| join type=inner dest [ | tstats `summariesonly` count values(All_Traffic.dest) as remote_dest values(All_Traffic.dest_port) as ports from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("msedge.exe","chrome.exe","firefox.exe","brave.exe") All_Traffic.dest_port IN (80,443) NOT (All_Traffic.dest="*.microsoft.com" OR All_Traffic.dest="*.office.com" OR All_Traffic.dest="*.microsoftonline.com") by All_Traffic.dest All_Traffic.src _time | `drop_dm_object_name(All_Traffic)` | rename src as dest_ip _time as netTime ]
| where netTime>=firstSeen AND netTime<=firstSeen+120
| table firstSeen netTime dest user svg_cmdline remote_dest
```

**Defender KQL:**
```kql
let SvgOpens = DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("msedge.exe","chrome.exe","firefox.exe","brave.exe","iexplore.exe")
| where ProcessCommandLine has ".svg"
| where ProcessCommandLine has_any (@"\INetCache\Content.Outlook\", @"\AppData\Local\Microsoft\Olk\Attachments\", @"\AppData\Local\Temp\", @"\Downloads\")
| project SvgTime=Timestamp, DeviceId, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, BrowserPid=ProcessId;
let ExtFetch = DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("msedge.exe","chrome.exe","firefox.exe","brave.exe")
| where RemotePort in (80,443)
| where not(RemoteUrl has_any ("microsoft.com","office.com","microsoftonline.com","office365.com","live.com","bing.com","windows.net"))
| project NetTime=Timestamp, DeviceId, BrowserPid=InitiatingProcessId, RemoteUrl, RemoteIP;
SvgOpens
| join kind=inner ExtFetch on DeviceId, BrowserPid
| where NetTime between (SvgTime .. SvgTime + 2m)
| summarize firstSeen=min(SvgTime), urls=make_set(RemoteUrl,25) by DeviceName, AccountName, ProcessCommandLine
```

### [LLM] Local HTML attachment launches browser then redirects to Tycoon2FA-pattern .ru AiTM landing

`UC_15_9` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as htmlOpenTime from datamodel=Endpoint.Processes where Processes.process_name IN ("msedge.exe","chrome.exe","firefox.exe","brave.exe") (Processes.process="*.htm *" OR Processes.process="*.html *" OR Processes.process="*.htm\"*" OR Processes.process="*.html\"*") (Processes.process="*\\INetCache\\Content.Outlook\\*" OR Processes.process="*\\AppData\\Local\\Microsoft\\Olk\\Attachments\\*" OR Processes.process="*\\AppData\\Local\\Temp\\*") by Processes.dest Processes.user Processes.process Processes.process_name
| `drop_dm_object_name(Processes)`
| join type=inner dest [ | tstats `summariesonly` count values(Web.url) as urls from datamodel=Web where (Web.url="*.ru/*" OR Web.url="*captcha*" OR Web.url="*verify*" OR Web.url="*human-check*" OR Web.url="*challenge*") Web.app IN ("msedge.exe","chrome.exe","firefox.exe","brave.exe") by Web.dest Web.url _time | `drop_dm_object_name(Web)` | rename _time as webTime ]
| where webTime>=htmlOpenTime AND webTime<=htmlOpenTime+180
| stats min(htmlOpenTime) as firstSeen values(process) as html_path values(urls) as visited_urls by dest user
```

**Defender KQL:**
```kql
let HtmlOpens = DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("msedge.exe","chrome.exe","firefox.exe","brave.exe")
| where ProcessCommandLine matches regex @"\.html?[\s\"']"
| where ProcessCommandLine has_any (@"\INetCache\Content.Outlook\", @"\AppData\Local\Microsoft\Olk\Attachments\", @"\AppData\Local\Temp\")
| project HtmlTime=Timestamp, DeviceId, DeviceName, AccountName, ProcessCommandLine, BrowserPid=ProcessId;
let SuspectFetch = DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("msedge.exe","chrome.exe","firefox.exe","brave.exe")
| where RemoteUrl matches regex @"\.ru(/|:|$)" or RemoteUrl has_any ("captcha","human-verify","challenge-platform","verify-you")
| project NetTime=Timestamp, DeviceId, BrowserPid=InitiatingProcessId, RemoteUrl, RemoteIP;
HtmlOpens
| join kind=inner SuspectFetch on DeviceId, BrowserPid
| where NetTime between (HtmlTime .. HtmlTime + 3m)
| summarize firstSeen=min(HtmlTime), urls=make_set(RemoteUrl,25), htmlPath=any(ProcessCommandLine) by DeviceName, AccountName
| extend Comment="Possible Tycoon2FA/Kratos/EvilTokens AiTM landing via HTML attachment chain"
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, AccountName, bin(Timestamp, 1m)
| where files > 200
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```


## Why this matters

Severity classified as **CRIT** based on: 10 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
