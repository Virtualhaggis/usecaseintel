# [HIGH] Attackers Deploy AiTM Phishing Pages to Access SharePoint, HubSpot, and Google Workspace

**Source:** Cyber Security News
**Published:** 2026-05-02
**Article:** https://cybersecuritynews.com/attackers-deploy-aitm-phishing-page/

## Threat Profile

Home Cyber Security News 
Attackers Deploy AiTM Phishing Pages to Access SharePoint, HubSpot, and Google Workspace 
By Dhivya 
May 2, 2026 
Threat actors are rapidly shifting their intrusion tradecraft toward high-speed, SaaS-centric attacks that completely bypass traditional endpoint security. 
Since October 2025, security researchers have tracked two distinct adversaries, identified as CORDIAL SPIDER and SNARKY SPIDER, conducting aggressive data theft campaigns. 
These groups operate almost ex…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `company-sso.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1564.008** — Hide Artifacts: Email Hiding Rules
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration
- **T1539** — Steal Web Session Cookie
- **T1530** — Data from Cloud Storage
- **T1213.002** — Data from Information Repositories: SharePoint
- **T1083** — File and Directory Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] CORDIAL/SNARKY SPIDER inbox rule suppressing 'alert', 'incident', 'MFA' notifications

`UC_6_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as command values(All_Changes.user) as user values(All_Changes.src) as src from datamodel=Change.All_Changes where All_Changes.action=created All_Changes.object_category="email-rule" (All_Changes.command="*New-InboxRule*" OR All_Changes.command="*Set-InboxRule*") (All_Changes.command="*alert*" OR All_Changes.command="*incident*" OR All_Changes.command="*MFA*" OR All_Changes.command="*security*" OR All_Changes.command="*phish*") (All_Changes.command="*DeleteMessage*" OR All_Changes.command="*MoveToFolder*" OR All_Changes.command="*MarkAsRead*" OR All_Changes.command="*JunkEmail*") by All_Changes.user All_Changes.src All_Changes.object | `drop_dm_object_name(All_Changes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// CORDIAL/SNARKY SPIDER — inbox rule that hides MFA / security notifications
let SuppressKeywords = dynamic(["alert","incident","mfa","security","phish","verify","sign-in","sign in","login","unusual","new device"]);
let SuppressActions = dynamic(["deletemessage","movetofolder","junkemail","markasread","forwardto","forwardasattachmentto","redirectto"]);
CloudAppEvents
| where Timestamp > ago(7d)
| where Application == "Microsoft Exchange Online"
| where ActionType in~ ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| extend Raw = tolower(tostring(RawEventData))
| where Raw has_any (SuppressActions)
| where Raw has_any (SuppressKeywords)
| extend RuleName = tostring(parse_json(RawEventData).Parameters)
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ISP, IsAnonymousProxy, UserAgent, ActionType, RuleName, RawEventData
| order by Timestamp desc
```

### [LLM] Existing MFA method deleted then new method registered within 30 minutes (AiTM persistence)

`UC_6_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as firstTime max(_time) as lastTime values(All_Changes.action) as actions values(All_Changes.src) as src values(All_Changes.user_agent) as user_agent from datamodel=Change.Account_Management where All_Changes.object_category="user" (All_Changes.command IN ("User registered security info","User deleted security info","Delete authentication method","Register security info","User registered all required security info","Update user")) by All_Changes.user _time span=1s | eval delete_time=if(match(actions,"(?i)delete|remove"), firstTime, null()), register_time=if(match(actions,"(?i)register|add"), lastTime, null()) | stats min(delete_time) as delete_time max(register_time) as register_time values(actions) as actions values(src) as src values(user_agent) as user_agent by All_Changes.user | where isnotnull(delete_time) AND isnotnull(register_time) AND (register_time - delete_time) <= 1800 AND (register_time - delete_time) >= 0 | rename All_Changes.user as user | `security_content_ctime(delete_time)` | `security_content_ctime(register_time)`
```

**Defender KQL:**
```kql
// CORDIAL/SNARKY SPIDER — MFA method swap (delete + register) <=30m by same UPN
let WindowMin = 30m;
let MfaDeletes = CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application == "Microsoft Azure AD" or ApplicationId == "00000003-0000-0000-c000-000000000000"
    | where ActionType has_any ("Delete authentication method","User deleted security info","Disable Strong Authentication","Admin disabled strong authentication")
    | project DeleteTime = Timestamp, AccountObjectId, AccountUpn = AccountDisplayName, DeleteIP = IPAddress, DeleteISP = ISP, DeleteUA = UserAgent, DeleteAction = ActionType;
let MfaRegisters = CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application == "Microsoft Azure AD" or ApplicationId == "00000003-0000-0000-c000-000000000000"
    | where ActionType has_any ("User registered security info","Register security info","Add authentication method","User registered all required security info","Register device")
    | project RegisterTime = Timestamp, AccountObjectId, RegisterIP = IPAddress, RegisterISP = ISP, RegisterUA = UserAgent, RegisterAction = ActionType;
MfaDeletes
| join kind=inner MfaRegisters on AccountObjectId
| where RegisterTime between (DeleteTime .. DeleteTime + WindowMin)
| extend DeltaSec = datetime_diff('second', RegisterTime, DeleteTime)
| project AccountUpn, AccountObjectId, DeleteTime, DeleteAction, DeleteIP, DeleteISP, DeleteUA,
          RegisterTime, RegisterAction, RegisterIP, RegisterISP, RegisterUA, DeltaSec
| order by DeleteTime desc
```

### [LLM] SaaS sensitive-term search ('confidential','SSN','contracts','VPN') followed by bulk download <1h

`UC_6_7` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.url) as urls values(Web.user_agent) as user_agent from datamodel=Web.Web where Web.app IN ("SharePoint","OneDrive","Google Workspace","GoogleDrive") (Web.action=search OR Web.http_method="GET") (Web.url="*confidential*" OR Web.url="*ssn*" OR Web.url="*contracts*" OR Web.url="*vpn*" OR Web.url="*passwords*") by Web.user _time span=10m | rename Web.user as user | join type=inner user [| tstats `summariesonly` count as DownloadCount values(Web.url) as DownloadedUrls from datamodel=Web.Web where Web.app IN ("SharePoint","OneDrive","Google Workspace","GoogleDrive") Web.action=download by Web.user _time span=10m | rename Web.user as user | where DownloadCount > 50] | table _time user count DownloadCount urls DownloadedUrls user_agent
```

**Defender KQL:**
```kql
// SNARKY/CORDIAL SPIDER — sensitive-keyword SaaS search, then bulk download within 1h
let SearchKeywords = dynamic(["confidential","ssn","social security","contracts","contract","vpn","passwords","secret"]);
let WindowMin = 60m;
let Searches = CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application in~ ("Microsoft SharePoint Online","Microsoft OneDrive for Business","Google Workspace","Google Drive")
    | where ActionType has_any ("SearchQueryPerformed","Search","SearchQuery")
    | extend QueryText = tolower(tostring(parse_json(tostring(RawEventData)).QueryText))
    | where QueryText has_any (SearchKeywords)
    | project SearchTime = Timestamp, AccountObjectId, AccountDisplayName, SearchIP = IPAddress, SearchISP = ISP, IsAnonymousProxy, UserAgent, QueryText;
let Downloads = CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application in~ ("Microsoft SharePoint Online","Microsoft OneDrive for Business","Google Workspace","Google Drive")
    | where ActionType has_any ("FileDownloaded","FileSyncDownloadedFull","FileAccessed","download")
    | summarize DownloadCount = count(), DownloadedFiles = make_set(ObjectName, 50), FirstDownload = min(Timestamp), LastDownload = max(Timestamp)
              by AccountObjectId, bin(Timestamp, 10m)
    | where DownloadCount > 50;
Searches
| join kind=inner Downloads on AccountObjectId
| where FirstDownload between (SearchTime .. SearchTime + WindowMin)
| extend MinutesToExfil = datetime_diff('minute', FirstDownload, SearchTime)
| project SearchTime, FirstDownload, MinutesToExfil, AccountDisplayName, AccountObjectId,
          QueryText, DownloadCount, DownloadedFiles, SearchIP, SearchISP, IsAnonymousProxy, UserAgent
| order by SearchTime desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `company-sso.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
