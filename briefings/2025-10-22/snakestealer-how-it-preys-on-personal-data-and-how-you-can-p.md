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
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1102** — Web Service
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1055.012** — Process Injection: Process Hollowing
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SnakeStealer exfiltration to Telegram Bot API from non-browser process

`UC_589_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.dest) as dest values(Web.user) as user from datamodel=Web where Web.url="*api.telegram.org/bot*" (Web.url="*sendMessage*" OR Web.url="*sendDocument*" OR Web.url="*sendPhoto*" OR Web.url="*getMe*") Web.app!="telegram*" by Web.src Web.process_name Web.app | `drop_dm_object_name(Web)` | where NOT match(process_name,"(?i)^(telegram|brave|chrome|firefox|msedge|iexplore|opera|safari)\.exe$") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// SnakeStealer Telegram-bot exfil: api.telegram.org from a non-browser process
let _browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","telegram.exe","telegramdesktop.exe","safari.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "api.telegram.org"
| where InitiatingProcessFileName !in~ (_browsers)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] SnakeStealer persistence: wscript.exe launching .vbs from Startup folder dropping .NET EXE in AppData

`UC_589_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd values(Processes.process_path) as process_path from datamodel=Endpoint.Processes where Processes.process_name="wscript.exe" (Processes.process="*\\Start Menu\\Programs\\Startup\\*.vbs*" OR Processes.process="*\\Startup\\*.vbs*") by Processes.dest Processes.user Processes.process_id Processes.parent_process_name | `drop_dm_object_name(Processes)` | join type=inner dest process_id [| tstats summariesonly=t values(Processes.process) as child_cmd values(Processes.process_path) as child_path values(Processes.process_name) as child_name from datamodel=Endpoint.Processes where (Processes.parent_process_name="wscript.exe" Processes.process_path="*\\AppData\\Local\\*" Processes.process_name="*.exe") by Processes.dest Processes.parent_process_id | rename Processes.parent_process_id as process_id | `drop_dm_object_name(Processes)`] | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
// SnakeStealer persistence: wscript.exe in Startup folder spawning EXE from %LocalAppData%
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "wscript.exe"
| where InitiatingProcessCommandLine has_any (@"\Start Menu\Programs\Startup\", @"\Startup\")
| where InitiatingProcessCommandLine has ".vbs"
| where FolderPath has @"\AppData\Local\" or FolderPath has @"\AppData\Roaming\"
| where FileName endswith ".exe"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentVbsCmd = InitiatingProcessCommandLine,
          ChildExe = FolderPath,
          ChildCmd = ProcessCommandLine,
          ChildSHA256 = SHA256,
          ProcessVersionInfoCompanyName, ProcessVersionInfoProductName
| order by Timestamp desc
```

### [LLM] SnakeStealer process-hollowing target RegSvcs.exe / RegAsm.exe / InstallUtil.exe egressing to public IP

`UC_589_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.process_name) as process_name from datamodel=Network_Traffic where All_Traffic.process_name IN ("RegSvcs.exe","RegAsm.exe","InstallUtil.exe","aspnet_compiler.exe","MSBuild.exe") AND NOT (All_Traffic.dest IN ("127.0.0.1","::1") OR cidrmatch("10.0.0.0/8",All_Traffic.dest) OR cidrmatch("172.16.0.0/12",All_Traffic.dest) OR cidrmatch("192.168.0.0/16",All_Traffic.dest)) by All_Traffic.src All_Traffic.user All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// SnakeStealer / Agent Tesla / FormBook process-hollowing target making outbound C2
let _hollow_targets = dynamic(["regsvcs.exe","regasm.exe","installutil.exe","aspnet_compiler.exe","msbuild.exe","caspol.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ (_hollow_targets)
| where RemoteIPType == "Public"
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            Connections = count(),
            DestIPs = make_set(RemoteIP, 25),
            DestUrls = make_set(RemoteUrl, 25),
            DestPorts = make_set(RemotePort, 10)
            by DeviceName, InitiatingProcessAccountName,
               InitiatingProcessFileName, InitiatingProcessSHA256,
               InitiatingProcessFolderPath, InitiatingProcessParentFileName
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


## Why this matters

Severity classified as **CRIT** based on: 7 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
