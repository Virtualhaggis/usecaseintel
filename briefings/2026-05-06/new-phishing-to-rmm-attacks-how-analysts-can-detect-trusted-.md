# [HIGH] New Phishing-to-RMM Attacks: How Analysts Can Detect Trusted-Tool Abuse Early

**Source:** Cyber Security News
**Published:** 2026-05-06
**Article:** https://cybersecuritynews.com/phishing-to-rmm-attacks-detection/

## Threat Profile

Home ANY.RUN 
New Phishing-to-RMM Attacks: How Analysts Can Detect Trusted-Tool Abuse Early  
By Balaji N 
May 6, 2026 




Detect Phishing-to-RMM Trusted Tool Abuse 
ANY.RUN researchers uncovered a phishing-to-RMM campaign in which attackers use fake Microsoft, Adobe, and OneDrive pages to deliver legitimate remote management tools such as ScreenConnect  and LogMeIn Rescue. 
Detection is difficult because the payload and infrastructure can look legitimate in isolation. Analysts need to conn…

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
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1566.002** — Phishing: Spearphishing Link
- **T1218.007** — System Binary Proxy Execution: Msiexec
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1562.001** — Impair Defenses: Disable or Modify Tools
- **T1553.005** — Subvert Trust Controls: Mark-of-the-Web Bypass
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Renamed RMM installer (ScreenConnect/LogMeIn) downloaded via browser as Adobe/Microsoft setup

`UC_4_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","outlook.exe","explorer.exe") AND (Processes.original_file_name IN ("ScreenConnect.ClientSetup.exe","ScreenConnect.WindowsClient.exe","LMI_Rescue.exe","Lmi_Rescue.exe","LogMeIn.exe","MeshAgent.exe","Action1_agent.exe","Syncro.Installer.exe","client32.exe","NetSupportManager.exe","SimpleHelpCustomer.exe","rustdesk.exe","SRServer.exe","AeroAdmin.exe","DattoRMMAgent.exe") OR Processes.process_company IN ("ConnectWise, LLC","ScreenConnect Software","LogMeIn, Inc.","GoTo Technologies USA, Inc.","Datto, Inc.","Action1 Corporation","Syncro","NetSupport Ltd","SimpleHelp","Splashtop Inc.","Open Source Developer, Sergiy Kovalenko")) AND (Processes.process_name IN ("Adobesetup.exe","AdobeSetup.exe","AdobeAcrobatSetup.exe","AcrobatReaderSetup.exe","AcroRdrDC.exe","OneDriveSetup.exe","MicrosoftStore.exe","MSStoreSetup.exe","PDFViewer.exe","PDF_Reader.exe","Document.exe","Invoice.exe") OR match(Processes.process_name,"(?i)^(adobe|acrobat|onedrive|microsoft|office|pdf|document|invoice|reader).*\.exe$")) by Processes.dest Processes.user Processes.process_name Processes.original_file_name Processes.process_company Processes.parent_process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | where original_file_name!=process_name | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let RmmOriginalNames = dynamic(["ScreenConnect.ClientSetup.exe","ScreenConnect.WindowsClient.exe","LMI_Rescue.exe","Lmi_Rescue.exe","LogMeIn.exe","MeshAgent.exe","Action1_agent.exe","Syncro.Installer.exe","client32.exe","NetSupportManager.exe","SimpleHelpCustomer.exe","rustdesk.exe","SRServer.exe","DattoRMMAgent.exe","AteraAgent.exe"]);
let RmmCompanies = dynamic(["ConnectWise, LLC","ScreenConnect Software","LogMeIn, Inc.","GoTo Technologies USA, Inc.","Datto, Inc.","Action1 Corporation","Syncro","NetSupport Ltd","SimpleHelp","Splashtop Inc.","TrustConnect Software PTY LTD"]);
let LureFileNames = dynamic(["Adobesetup.exe","AdobeSetup.exe","AdobeAcrobatSetup.exe","AcrobatReaderSetup.exe","AcroRdrDC.exe","OneDriveSetup.exe","MicrosoftStore.exe","MSStoreSetup.exe","PDFViewer.exe","PDF_Reader.exe","Document.exe","Invoice.exe","Statement.exe"]);
let Browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","arc.exe","outlook.exe","explorer.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ (Browsers)
| where (ProcessVersionInfoOriginalFileName in~ (RmmOriginalNames) or ProcessVersionInfoCompanyName in~ (RmmCompanies))
| where FileName in~ (LureFileNames) or FileName matches regex @"(?i)^(adobe|acrobat|onedrive|microsoft|ms[-_]?store|office|pdf|document|invoice|reader|statement).{0,30}\.exe$"
| where ProcessVersionInfoOriginalFileName !~ FileName
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
          OriginalFileName = ProcessVersionInfoOriginalFileName,
          CompanyName = ProcessVersionInfoCompanyName,
          ProductName = ProcessVersionInfoProductName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          ChildCmd = ProcessCommandLine
| order by Timestamp desc
```

### [LLM] VBS-spawned msiexec quiet install of LogMeIn Rescue / RMM with SmartScreen or MOTW tampering

`UC_4_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe","cscript.exe") AND Processes.process_name="msiexec.exe" AND (Processes.process IN ("*\/quiet*","*\/qn*","*\/qb*","*-quiet*","*-qn*")) AND (Processes.process IN ("*LogMeIn*","*Rescue*","*LMI_*","*Lmi_Rescue*","*ScreenConnect*","*ConnectWise*","*MeshAgent*","*Action1*","*Syncro*","*NetSupport*","*SimpleHelp*","*RustDesk*","*Splashtop*","*Datto*","*ITarian*") OR Processes.process LIKE "%http%.msi%") by Processes.dest Processes.user Processes.parent_process Processes.parent_process_id Processes.process Processes.process_id _time | `drop_dm_object_name(Processes)` | rename _time AS msi_time | join type=left dest [ | tstats `summariesonly` min(_time) as smartscreen_time from datamodel=Endpoint.Registry where (Registry.registry_path IN ("*\\System\\SmartScreenEnabled*","*\\Microsoft\\Windows\\System\\EnableSmartScreen*","*\\Edge\\SmartScreenEnabled*","*\\Attachments\\SaveZoneInformation*")) AND Registry.registry_value_data IN ("Off","0","1") by Registry.dest | `drop_dm_object_name(Registry)`] | where isnull(smartscreen_time) OR abs(msi_time - smartscreen_time) <= 600 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let RmmHints = dynamic(["LogMeIn","Rescue","LMI_","Lmi_Rescue","ScreenConnect","ConnectWise","MeshAgent","Action1","Syncro","NetSupport","SimpleHelp","RustDesk","Splashtop","Datto","ITarian"]);
let VbsToMsiQuiet = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
    | where FileName =~ "msiexec.exe"
    | where ProcessCommandLine has_any ("/quiet","/qn","/qb","-quiet")
    | where ProcessCommandLine has_any (RmmHints)
        or ProcessCommandLine matches regex @"(?i)https?://[^\s\"]+\.msi\b"
    | project MsiTime = Timestamp, DeviceId, DeviceName, AccountName,
              VbsCmd = InitiatingProcessCommandLine,
              VbsParent = InitiatingProcessParentFileName,
              MsiCmd = ProcessCommandLine,
              ProcessIntegrityLevel;
let DefenderTamper = DeviceRegistryEvents
    | where Timestamp > ago(7d)
    | where (RegistryKey has_any (@"\SmartScreenEnabled", @"\Microsoft\Windows\System\EnableSmartScreen", @"\Edge\SmartScreenEnabled", @"\Attachments\SaveZoneInformation", @"\Windows Defender\Real-Time Protection")
              and RegistryValueData in~ ("Off","0","1"))
    | project RegTime = Timestamp, DeviceId, RegistryKey, RegistryValueName, RegistryValueData,
              RegInitiator = InitiatingProcessFileName;
VbsToMsiQuiet
| join kind=leftouter DefenderTamper on DeviceId
| where isnull(RegTime) or abs(datetime_diff('minute', MsiTime, RegTime)) <= 5
| project MsiTime, DeviceName, AccountName, VbsCmd, MsiCmd, ProcessIntegrityLevel,
          RegistryKey, RegistryValueName, RegistryValueData, RegInitiator
| order by MsiTime desc
```

### [LLM] RMM client installer / VBS dropper downloaded from n8n.cloud workflow domain

`UC_4_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*n8n.cloud*" OR Web.url="*vmail.app.n8n.cloud*") by Web.src Web.user Web.url Web.http_user_agent Web.dest | `drop_dm_object_name(Web)` | rename src AS dest | join type=inner dest [ | tstats `summariesonly` min(_time) as file_time values(Filesystem.file_name) as file_name values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("ScreenConnect.ClientSetup.exe","ScreenConnect.WindowsClient.exe","LMI_Rescue.exe","Lmi_Rescue.exe","LogMeIn.exe","MeshAgent.exe","Action1_agent.exe","client32.exe","rustdesk.exe","DattoRMMAgent.exe","Adobesetup.exe","AdobeSetup.exe","AcrobatReaderSetup.exe","OneDriveSetup.exe") OR Filesystem.file_name="*.vbs" OR Filesystem.file_name="*.msi") AND Filesystem.action="created" by Filesystem.dest] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LureFileNames = dynamic(["ScreenConnect.ClientSetup.exe","ScreenConnect.WindowsClient.exe","LMI_Rescue.exe","Lmi_Rescue.exe","LogMeIn.exe","MeshAgent.exe","Action1_agent.exe","client32.exe","rustdesk.exe","DattoRMMAgent.exe","Adobesetup.exe","AdobeSetup.exe","AcrobatReaderSetup.exe","OneDriveSetup.exe","AdobeAcrobatSetup.exe"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed")
| where (FileOriginUrl has "n8n.cloud" or FileOriginReferrerUrl has "n8n.cloud")
| where FileName in~ (LureFileNames)
   or FileName endswith ".vbs"
   or FileName endswith ".msi"
   or FileName endswith ".exe"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","arc.exe","outlook.exe","explorer.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, SHA256, FileSize,
          FileOriginUrl, FileOriginReferrerUrl, FileOriginIP,
          DownloadedBy = InitiatingProcessFileName
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — New Phishing-to-RMM Attacks: How Analysts Can Detect Trusted-Tool Abuse Early

`UC_4_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New Phishing-to-RMM Attacks: How Analysts Can Detect Trusted-Tool Abuse Early ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("adobesetup.exe","screenconnect.clientsetup.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("adobesetup.exe","screenconnect.clientsetup.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New Phishing-to-RMM Attacks: How Analysts Can Detect Trusted-Tool Abuse Early
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("adobesetup.exe", "screenconnect.clientsetup.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("adobesetup.exe", "screenconnect.clientsetup.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 10 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
