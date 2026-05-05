# [CRIT] Email Bombing and Fake IT Support Calls Fuel New Microsoft Teams Phishing Attacks

**Source:** Cyber Security News
**Published:** 2026-05-04
**Article:** https://cybersecuritynews.com/email-bombing-and-fake-it-support-calls/

## Threat Profile

Home Cyber Security News 
Email Bombing and Fake IT Support Calls Fuel New Microsoft Teams Phishing Attacks 
By Tushar Subhra Dutta 
May 4, 2026 
A new wave of cyberattacks is targeting employees through a combination of inbox flooding and fake IT support contacts on Microsoft Teams, tricking users into handing over remote access to their own devices. 
These attacks have been growing steadily since the start of 2026, and security researchers warn they are far from slowing down. 
The attack usual…

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
- **T1566.004** — Phishing: Spearphishing Voice
- **T1566** — Phishing
- **T1219** — Remote Access Software
- **T1567** — Exfiltration Over Web Service
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1566.003** — Phishing: Spearphishing via Service
- **T1656** — Impersonation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Quick Assist drops UNC6692 'Email-Deployment-Process-System.zip' lure

`UC_15_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_name="Email-Deployment-Process-System.zip" OR (Filesystem.file_name="*.zip" AND Filesystem.file_name="*Email-Deployment-Process-System*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
// UNC6692 — Email-Deployment-Process-System.zip dropped on disk
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType == "FileCreated"
| where FileName =~ "Email-Deployment-Process-System.zip"
    or (FileName endswith ".zip" and FileName has "Email-Deployment-Process-System")
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, SHA256,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName,
          InitiatingProcessAccountName, FileOriginUrl, FileOriginIP
| order by Timestamp desc
```

### [LLM] WinSCP / RClone / FileZilla / MegaSync executed within a Quick Assist or AnyDesk session

`UC_15_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as qa_start max(_time) as qa_end from datamodel=Endpoint.Processes where (Processes.process_name="quickassist.exe" OR Processes.process_name="msra.exe" OR Processes.process_name="QuickAssistApp.exe" OR Processes.process_name="AnyDesk.exe") by Processes.dest | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats `summariesonly` count min(_time) as exfil_first values(Processes.process) as exfil_cmdline values(Processes.user) as user values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="WinSCP.exe" OR Processes.process_name="WinSCP.com" OR Processes.process_name="rclone.exe" OR Processes.process_name="filezilla.exe" OR Processes.process_name="MEGAsync.exe" OR Processes.process_name="MEGAsyncservice.exe") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)`] | where exfil_first >= qa_start AND exfil_first <= (qa_end + 3600) | convert ctime(qa_start) ctime(qa_end) ctime(exfil_first)
```

**Defender KQL:**
```kql
// Quick Assist / AnyDesk session followed by exfil tooling on the same host
let LookbackHours = 24h;
let WindowSec = 3600;            // 1 hour after the QA/AnyDesk session ends
let RemoteAccessBins = dynamic(["quickassist.exe","msra.exe","quickassistapp.exe","anydesk.exe"]);
let ExfilBins = dynamic(["winscp.exe","winscp.com","rclone.exe","filezilla.exe","megasync.exe","megasyncservice.exe"]);
let RASessions = DeviceProcessEvents
    | where Timestamp > ago(LookbackHours)
    | where FileName in~ (RemoteAccessBins)
         or InitiatingProcessFileName in~ (RemoteAccessBins)
    | summarize RAStart = min(Timestamp), RAEnd = max(Timestamp),
                RABins = make_set(FileName)
                by DeviceId, DeviceName;
DeviceProcessEvents
| where Timestamp > ago(LookbackHours)
| where AccountName !endswith "$"
| where FileName in~ (ExfilBins)
     or InitiatingProcessFileName in~ (ExfilBins)
     or ProcessCommandLine has_any ("WinSCP","rclone ","MEGAsync")
| join kind=inner RASessions on DeviceId
| where Timestamp between (RAStart .. RAEnd + WindowSec * 1s)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RAStart, RAEnd, RABins
| order by Timestamp desc
```

### [LLM] External Microsoft Teams contact from helpdesk-themed display name (UNC6692 / Scattered Spider lure)

`UC_15_7` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`o365_management_activity` Workload=MicrosoftTeams Operation IN ("MemberAdded","MessageSent","ChatCreated","MessageCreatedHasLink") (ExternalAccess=true OR UserId="*#EXT#*" OR UserType="Guest") | rex field=_raw "(?i)(?<impersonation>IT[\s\-]?(Protection|Support|Department|Help|Desk)|Help[\s\-]?Desk|Windows[\s\-]?Security|Security[\s\-]?Help[\s\-]?Desk)" | where isnotnull(impersonation) | stats min(_time) as firstSeen max(_time) as lastSeen values(UserId) as senders values(ClientIP) as src_ip values(Operation) as ops by impersonation
```

**Defender KQL:**
```kql
// External Teams contact from a helpdesk-themed display name (UNC6692 lure)
let _internal_domain = "yourdomain.com";   // <-- replace with your verified domain
let _impersonation = @"(?i)(IT[\s\-]?(Protection|Support|Department|Help|Desk)|Help[\s\-]?Desk|Windows[\s\-]?Security|Security[\s\-]?Help[\s\-]?Desk)";
CloudAppEvents
| where Timestamp > ago(7d)
| where Application =~ "Microsoft Teams"
| where ActionType has_any ("MessageSent","ChatCreated","MemberAdded",
                            "ChatMessageReceived","MessageCreatedHasLink",
                            "MessageReceived")
| extend Raw = parse_json(RawEventData)
| extend SenderUpn = tostring(coalesce(Raw.UserId, Raw.SenderId))
| extend ExternalSender = (AccountType =~ "Guest")
                       or (isnotempty(SenderUpn) and SenderUpn !endswith _internal_domain)
                       or (AccountDisplayName has "#EXT#")
| where ExternalSender
| where AccountDisplayName matches regex _impersonation
     or tostring(ObjectName)   matches regex _impersonation
| project Timestamp, AccountDisplayName, SenderUpn, AccountType, IPAddress,
          CountryCode, ISP, ActionType, ObjectName, ApplicationId, RawEventData
| order by Timestamp desc
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


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
