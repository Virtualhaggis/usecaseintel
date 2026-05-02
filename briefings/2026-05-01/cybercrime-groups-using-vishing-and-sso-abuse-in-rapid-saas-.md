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
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1098** — Account Manipulation
- **T1567** — Exfiltration Over Web Service
- **T1530** — Data from Cloud Storage
- **T1213.002** — Data from Information Repositories: SharePoint

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Cordial/Snarky Spider: MFA device deleted then new device registered within short window

`UC_7_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as firstTime max(_time) as lastTime values(All_Changes.action) as actions values(All_Changes.object) as objects values(All_Changes.src) as src_ips values(All_Changes.user_agent) as ua from datamodel=Change.Account_Management where All_Changes.object_category="User" (All_Changes.action="Delete device" OR All_Changes.action="Update user" OR All_Changes.action="Register device" OR All_Changes.action="Add registered owner to device" OR All_Changes.action="User registered security info" OR All_Changes.action="User deleted security info") by All_Changes.user _time span=1m | `drop_dm_object_name(All_Changes)` | eventstats values(action) as window_actions by user | where like(window_actions,"%Delete%") AND (like(window_actions,"%Register%") OR like(window_actions,"%registered security info%")) | transaction user maxspan=15m | where eventcount>=2 | table firstTime lastTime user actions src_ips ua
```

**Defender KQL:**
```kql
// Cordial/Snarky Spider MFA swap: delete then add device for same identity within 15 min
let window = 15m;
let deletes = CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft Azure","Office 365","Microsoft Entra ID")
| where ActionType in ("Delete device.","Delete device","User deleted security info.","Disable Strong Authentication.","Update user.")
| extend Upn = tolower(tostring(AccountObjectId)), DelTime = Timestamp, DelAction = ActionType, DelIP = IPAddress;
let adds = CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft Azure","Office 365","Microsoft Entra ID")
| where ActionType in ("Register device.","Add registered owner to device.","User registered security info.","Add user.","Update user.")
| extend Upn = tolower(tostring(AccountObjectId)), AddTime = Timestamp, AddAction = ActionType, AddIP = IPAddress;
deletes
| join kind=inner adds on Upn
| where AddTime between (DelTime .. (DelTime + window))
| project DelTime, AddTime, AccountUpn=AccountDisplayName, Upn, DelAction, AddAction, DelIP, AddIP
| extend NewIPDiffersFromOld = tostring(DelIP) != tostring(AddIP)
```

### [LLM] Inbox rule auto-deleting Entra/Exchange MFA & device-registration notifications

`UC_7_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as cmd values(All_Changes.src) as src values(All_Changes.user_agent) as ua from datamodel=Change.All_Changes where All_Changes.object_category="InboxRule" (All_Changes.action="created" OR All_Changes.action="modified" OR All_Changes.command="New-InboxRule" OR All_Changes.command="Set-InboxRule" OR All_Changes.command="UpdateInboxRules") by All_Changes.user All_Changes.object | `drop_dm_object_name(All_Changes)` | rex field=cmd "(?i)(?<rule_body>SubjectContainsWords|BodyContainsWords|SubjectOrBodyContainsWords)[^\"]*\"(?<rule_keywords>[^\"]+)\"" | rex field=cmd "(?i)(?<rule_action>DeleteMessage|MoveToFolder|MarkAsRead)" | where match(rule_keywords,"(?i)security info|MFA|multi.?factor|device.?regist|unusual sign|new sign.?in|microsoft account|verification code|authenticator|Okta|Duo|conditional access") AND isnotnull(rule_action) | table firstTime user object rule_keywords rule_action src ua
```

**Defender KQL:**
```kql
// Inbox rules silencing identity / MFA / device-registration alert mail
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft Exchange Online","Office 365")
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules","New-MailboxRule")
| extend Params = tostring(RawEventData)
| where Params has_any ("DeleteMessage","MoveToFolder","MarkAsRead")
| where Params matches regex @"(?i)security ?info|MFA|multi.?factor|device ?regist|unusual sign.?in|new sign.?in|microsoft account team|verification code|authenticator|conditional access|Okta|Duo|sign.?in activity"
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType, IPAddress, UserAgent, ISP, CountryCode, Params
| join kind=leftouter (
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | summarize SignInIPs=make_set(IPAddress), ASNs=make_set(NetworkLocationDetails) by AccountObjectId
) on AccountObjectId
```

### [LLM] Bulk SaaS data export from Salesforce/SharePoint/HubSpot/Google Workspace within 1h of new MFA device

`UC_7_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as regTime values(All_Changes.src) as reg_src from datamodel=Change.Account_Management where (All_Changes.action="Register device" OR All_Changes.action="User registered security info" OR All_Changes.action="Add registered owner to device") by All_Changes.user | `drop_dm_object_name(All_Changes)` | rename user as actor | join type=inner actor [| tstats `summariesonly` count sum(Web.bytes_out) as bytes_out values(Web.url) as urls values(Web.dest) as dest from datamodel=Web where Web.app IN ("salesforce","sharepoint","hubspot","google-drive","google-workspace","gws") (Web.action="download" OR Web.action="export" OR Web.http_method="GET") by Web.user _time span=10m | `drop_dm_object_name(Web)` | rename user as actor | where count>=50 OR bytes_out>=104857600] | eval delta=(_time-regTime) | where delta>=0 AND delta<=3600 | table regTime _time actor reg_src dest count bytes_out urls
```

**Defender KQL:**
```kql
// Mass SaaS export within 1h of new MFA device registration
let window = 1h;
let newDevice = CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Register device.","Add registered owner to device.","User registered security info.")
| project RegTime=Timestamp, AccountObjectId, RegIP=IPAddress, RegISP=ISP;
let exfil = CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Salesforce","Microsoft SharePoint Online","Microsoft OneDrive for Business","HubSpot","Google Drive","Google Workspace")
| where ActionType has_any ("FileDownloaded","FileSyncDownloadedFull","FileAccessed","Report Export","DataExport","BulkApi","download","Export","drive.files.download")
| summarize ActionCount=count(), Apps=make_set(Application), Files=make_set(ObjectName, 100), ExfilIPs=make_set(IPAddress), ExfilISPs=make_set(ISP) by AccountObjectId, bin(Timestamp, 10m)
| where ActionCount >= 50;
newDevice
| join kind=inner exfil on AccountObjectId
| where Timestamp between (RegTime .. (RegTime + window))
| extend MinutesAfterReg = datetime_diff('minute', Timestamp, RegTime)
| project RegTime, ExfilStart=Timestamp, MinutesAfterReg, AccountObjectId, RegIP, RegISP, ExfilIPs, ExfilISPs, Apps, ActionCount, Files
| order by ExfilStart desc
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 12 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
