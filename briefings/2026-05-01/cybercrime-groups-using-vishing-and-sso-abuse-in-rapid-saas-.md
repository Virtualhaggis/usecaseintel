# [CRIT] Cybercrime Groups Using Vishing and SSO Abuse in Rapid SaaS Extortion Attacks

**Source:** The Hacker News
**Published:** 2026-05-01
**Article:** https://thehackernews.com/2026/05/cybercrime-groups-using-vishing-and-sso.html

## Threat Profile

Cybercrime Groups Using Vishing and SSO Abuse in Rapid SaaS Extortion Attacks 
 Ravie Lakshmanan  May 01, 2026 
Cybersecurity researchers are warning of two cybercrime groups that are carrying out "rapid, high-impact attacks" operating almost within the confines of SaaS environments, while leaving minimal traces of their actions.
The clusters, Cordial Spider (aka BlackFile, CL-CRI-1116, O-UNC-045, and UNC6671) and Snarky Spider (aka O-UNC-025 and UNC6661), have been attributed to high-speed da…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
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
- **T1195.002** — Compromise Software Supply Chain
- **T1098.005** — Account Manipulation: Device Registration
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1621** — Multi-Factor Authentication Request Generation
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1098** — Account Manipulation
- **T1562.006** — Impair Defenses: Indicator Blocking
- **T1530** — Data from Cloud Storage
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1090.002** — Proxy: External Proxy

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Cordial/Snarky Spider MFA bypass: auth device removed then new device registered within 30 min by same actor

`UC_60_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as removed_time from datamodel=Change where (All_Changes.action IN ("deleted","removed","disabled")) AND (All_Changes.object_category="user" OR All_Changes.object_category="device") AND (All_Changes.command IN ("Delete device","Remove registered owner from device","Delete strong authentication method","Disable Strong Authentication","User deleted security info")) by All_Changes.user All_Changes.src All_Changes.object | `drop_dm_object_name(All_Changes)` | rename src as removed_ip, object as removed_object | join type=inner user [| tstats `summariesonly` count min(_time) as added_time from datamodel=Change where (All_Changes.action IN ("created","added","enabled","modified")) AND (All_Changes.command IN ("Add device","Register device","Add registered owner to device","Add strong authentication method","User registered security info","Update authentication method")) by All_Changes.user All_Changes.src All_Changes.object | `drop_dm_object_name(All_Changes)` | rename src as added_ip, object as added_object] | where added_time>=removed_time AND added_time<=removed_time+1800 | eval delay_sec=added_time-removed_time | table user removed_time removed_object removed_ip added_time added_object added_ip delay_sec | sort - removed_time
```

**Defender KQL:**
```kql
let Window = 30m;
let RemovalActions = dynamic(["Delete device","Remove device","Remove registered owner from device","Delete strong authentication method","Disable Strong Authentication","User deleted security info"]);
let AddActions = dynamic(["Add device","Register device","Add registered owner to device","Add strong authentication method","User registered security info","Update authentication method","Enable Strong Authentication"]);
let Removed = CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application has_any ("Microsoft Entra ID","Office 365","Azure Active Directory","Microsoft Graph")
    | where ActionType in~ (RemovalActions)
    | project RemovedTime = Timestamp, AccountObjectId, AccountDisplayName, RemovedAction = ActionType, RemovedIp = IPAddress, RemovedISP = ISP, RemovedObject = ObjectName;
let Added = CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application has_any ("Microsoft Entra ID","Office 365","Azure Active Directory","Microsoft Graph")
    | where ActionType in~ (AddActions)
    | project AddedTime = Timestamp, AccountObjectId, AccountDisplayName, AddedAction = ActionType, AddedIp = IPAddress, AddedISP = ISP, AddedObject = ObjectName;
Removed
| join kind=inner Added on AccountObjectId
| where AddedTime between (RemovedTime .. RemovedTime + Window)
| project AccountObjectId, AccountDisplayName, RemovedTime, RemovedAction, RemovedObject, RemovedIp, RemovedISP, AddedTime, AddedAction, AddedObject, AddedIp, AddedISP,
          DelaySec = datetime_diff('second', AddedTime, RemovedTime)
| order by RemovedTime desc
```

### [LLM] Inbox rule auto-deleting Microsoft account-security / new-device-registration notifications (Cordial/Snarky Spider TTP)

`UC_60_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Change where All_Changes.command IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Update-InboxRule") by _time All_Changes.user All_Changes.src All_Changes.command All_Changes.object All_Changes.object_attrs | `drop_dm_object_name(All_Changes)` | where match(object_attrs,"(?i)(device registered|security info|unfamiliar (sign\-in|device)|accountprotection\.microsoft\.com|account\.microsoft\.com|new sign\-in|security alert|verify your identity|registered a new|your security info changed|account\-security\-noreply)") AND match(object_attrs,"(?i)(DeleteMessage|MoveToFolder|MarkAsRead|Deleted Items|RSS Feeds|Junk|Archive|Conversation History)") | table _time user src command object object_attrs | sort - _time
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in~ ("New-InboxRule","Set-InboxRule","UpdateInboxRules","Update-InboxRule")
| extend Raw = tostring(RawEventData)
| where Raw matches regex @"(?i)(device registered|security info|unfamiliar (sign-in|device)|accountprotection\.microsoft\.com|account\.microsoft\.com|new sign-in|security alert|verify your identity|registered a new|your security info changed|account-security-noreply)"
| where Raw matches regex @"(?i)(DeleteMessage|MoveToFolder|MarkAsRead|Deleted Items|RSS Feeds|Junk|Archive|Conversation History)"
| project Timestamp, AccountObjectId, AccountDisplayName, IPAddress, ISP, CountryCode, IsAnonymousProxy, UserAgent, ActionType, ObjectName, Raw
| order by Timestamp desc
```

### [LLM] Rapid SaaS bulk exfil from anonymous/residential-proxy IP within 1 hour of SSO sign-in (Snarky/Cordial Spider speedrun)

`UC_60_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as signin_time from datamodel=Authentication where Authentication.action="success" AND (Authentication.signature_id="AnonymousProxy" OR Authentication.risk_level IN ("medium","high") OR Authentication.tag="anonymous_ip") by Authentication.user Authentication.src Authentication.app | `drop_dm_object_name(Authentication)` | rename src as signin_ip, app as signin_app | join type=inner user [| tstats `summariesonly` count dc(All_Changes.object) as file_count values(All_Changes.object) as files values(All_Changes.src) as download_ips min(_time) as first_download max(_time) as last_download from datamodel=Change where All_Changes.action IN ("read","downloaded") AND All_Changes.command IN ("FileDownloaded","FileSyncDownloadedFull","FileAccessed","FilePreviewed","ExportFile","Reports.Export","Object.Download") AND All_Changes.dest IN ("SharePoint","OneDrive","HubSpot","Salesforce","Google Workspace","Google Drive") by All_Changes.user | `drop_dm_object_name(All_Changes)`] | where first_download>=signin_time AND first_download<=signin_time+3600 AND file_count>=25 | table user signin_time signin_ip signin_app first_download last_download file_count download_ips files | sort - first_download
```

**Defender KQL:**
```kql
let Window = 1h;
let MinFiles = 25;
let RiskySignIns = AADSignInEventsBeta
    | where Timestamp > ago(1d)
    | where ErrorCode == 0
    | where IsAnonymousProxy == true or RiskLevelDuringSignIn in ("medium","high") or RiskState in ("atRisk","confirmedCompromised")
    | project SignInTime = Timestamp, AccountObjectId, AccountUpn, SignInIp = IPAddress, SignInCountry = Country, SignInApp = Application;
let SaaSReads = CloudAppEvents
    | where Timestamp > ago(1d)
    | where Application in~ ("Microsoft SharePoint Online","Microsoft OneDrive for Business","HubSpot","Salesforce","Google Workspace","Google Drive")
    | where ActionType has_any ("FileDownloaded","FileSyncDownloadedFull","FileAccessed","FilePreviewed","ExportFile","Reports.Export","Object.Download","Download")
    | project DownloadTime = Timestamp, AccountObjectId, DownloadApp = Application, DownloadIp = IPAddress, DownloadISP = ISP, DownloadObject = ObjectName, DownloadIsAnonProxy = IsAnonymousProxy;
RiskySignIns
| join kind=inner SaaSReads on AccountObjectId
| where DownloadTime between (SignInTime .. SignInTime + Window)
| summarize FileCount = dcount(DownloadObject),
            SampleFiles = make_set(DownloadObject, 25),
            DownloadIps = make_set(DownloadIp, 5),
            DownloadISPs = make_set(DownloadISP, 5),
            FirstDownload = min(DownloadTime),
            LastDownload = max(DownloadTime)
            by AccountObjectId, AccountUpn, DownloadApp, SignInTime, SignInIp, SignInCountry
| where FileCount >= MinFiles
| order by FirstDownload desc
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
