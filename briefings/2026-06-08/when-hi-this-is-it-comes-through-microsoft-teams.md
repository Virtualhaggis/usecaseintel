# [HIGH] When “Hi, This Is IT” Comes Through Microsoft Teams

**Source:** Unit 42 (Palo Alto)
**Published:** 2026-06-08
**Article:** https://unit42.paloaltonetworks.com/microsoft-teams-phishing/

## Threat Profile

Threat Research Center 
Insights 
General 
General 
When “Hi, This Is IT” Comes Through Microsoft Teams 
6 min read 
Related Products Unit 42 Incident Response 
By: Bill Batchelor 
Published: June 8, 2026 
Categories: General 
Insights 
Tags: Cloaked Ursa 
Identity 
Phishing 
Social engineering 
"Hi, IT Department Here!" 
It's Friday afternoon. The week has been busy, and everyone is wrapping up before the weekend. One of your workers receives a message (Figure 1) through Microsoft Teams from wh…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `ommicrosoft.com`

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1566.003** — Phishing: Spearphishing via Service
- **T1585.002** — Establish Accounts: Email Accounts
- **T1656** — Impersonation
- **T1585** — Establish Accounts
- **T1199** — Trusted Relationship
- **T1621** — Multi-Factor Authentication Request Generation
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] External MS Teams chat from typosquatted Microsoft-themed tenant domain (ommicrosoft.com)

`UC_2_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.dest) as dest from datamodel=Authentication where Authentication.app="MicrosoftTeams" (Authentication.user="*@ommicrosoft.com" OR Authentication.src_user="*@ommicrosoft.com" OR Authentication.user="*ommicrosoft*") by Authentication.user Authentication.src_user Authentication.dest_user Authentication.action | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where Application =~ "Microsoft Teams"
| where ActionType in~ ("ChatCreated", "MessageSent", "MemberAdded", "MessageCreatedHasLink", "MessageCreatedNotification")
| extend RawData = tostring(RawEventData)
| where AccountDisplayName has "ommicrosoft" 
    or RawData has "ommicrosoft.com" 
    or AdditionalFields has "ommicrosoft"
| project Timestamp, ActionType, AccountDisplayName, AccountObjectId, ObjectName, IPAddress, CountryCode, UserAgent, RawEventData
| order by Timestamp desc
```

### [LLM] External MS Teams chat from sender with IT/helpdesk/support display name

`UC_2_8` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Authentication.dest_user) as recipients from datamodel=Authentication where Authentication.app="MicrosoftTeams" Authentication.action="ChatCreated" (Authentication.src_user_display="*IT *" OR Authentication.src_user_display="*Help*Desk*" OR Authentication.src_user_display="*Service*Desk*" OR Authentication.src_user_display="*IT Support*" OR Authentication.src_user_display="*Tech Support*" OR Authentication.src_user_display="*Security Team*" OR Authentication.src_user_display="*IT Department*" OR Authentication.src_user_display="*Microsoft Support*") by Authentication.src_user Authentication.src_user_display | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime) | where count >= 1
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where Application =~ "Microsoft Teams"
| where ActionType in~ ("ChatCreated", "MessageSent", "MemberAdded")
| extend SenderUpn = tostring(RawEventData.UserId), SenderDisplay = tostring(AccountDisplayName), Participants = tostring(RawEventData.ParticipantInfo)
| where AccountType =~ "Guest" or Participants has "ExternalUser" or RawEventData has "HasForeignTenantUsers"
| where SenderDisplay matches regex @"(?i)(IT[\s\-]?(Dept|Department|Support|Helpdesk|Team)|Help[\s\-]?Desk|Service[\s\-]?Desk|Tech[\s\-]?Support|Security[\s\-]?(Team|Operations)|Microsoft[\s\-]?Support|M365[\s\-]?Admin|O365[\s\-]?Admin)"
| project Timestamp, ActionType, SenderUpn, SenderDisplay, AccountObjectId, IPAddress, CountryCode, ObjectName, RawEventData
| order by Timestamp desc
```

### [LLM] First-time external M365 tenant initiating MS Teams chats with internal users

`UC_2_9` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as firstSeen max(_time) as lastSeen count from datamodel=Authentication where Authentication.app="MicrosoftTeams" Authentication.action IN ("ChatCreated","MessageSent","MemberAdded") earliest=-60d@d by Authentication.src_user_domain | `drop_dm_object_name(Authentication)` | where firstSeen >= relative_time(now(), "-24h") AND src_user_domain!="<your-corp-domain>" | convert ctime(firstSeen) ctime(lastSeen)
```

**Defender KQL:**
```kql
let Baseline = CloudAppEvents
    | where Timestamp between (ago(60d) .. ago(24h))
    | where Application =~ "Microsoft Teams"
    | where ActionType in~ ("ChatCreated", "MessageSent", "MemberAdded")
    | extend SenderDomain = tolower(tostring(split(AccountDisplayName, "@")[1]))
    | extend SenderDomainRaw = tolower(extract(@"@([A-Za-z0-9\-\.]+)", 1, tostring(RawEventData)))
    | summarize by SenderDomain = coalesce(SenderDomain, SenderDomainRaw);
CloudAppEvents
| where Timestamp > ago(24h)
| where Application =~ "Microsoft Teams"
| where ActionType in~ ("ChatCreated", "MessageSent", "MemberAdded")
| extend SenderDomain = tolower(extract(@"@([A-Za-z0-9\-\.]+)", 1, tostring(RawEventData)))
| where isnotempty(SenderDomain) and SenderDomain !endswith "<your-corp-domain>"
| join kind=leftanti Baseline on SenderDomain
| summarize FirstSeen = min(Timestamp), ChatCount = count(), InternalRecipients = dcount(ObjectId), SampleSender = any(AccountDisplayName), SampleIP = any(IPAddress) by SenderDomain
| order by FirstSeen desc
```

### [LLM] MFA push approval within minutes of external Teams chat (social-engineering chain)

`UC_2_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as chatTime from datamodel=Authentication where Authentication.app="MicrosoftTeams" Authentication.action="ChatCreated" by Authentication.dest_user Authentication.src_user | `drop_dm_object_name(Authentication)` | rename dest_user as user src_user as external_sender | join type=inner user [| tstats `summariesonly` min(_time) as signinTime values(Authentication.src) as signin_ip from datamodel=Authentication where Authentication.app="AzureActiveDirectory" Authentication.action="success" Authentication.authentication_method="MFA" by Authentication.user | `drop_dm_object_name(Authentication)` | rename user as user] | eval delta_sec=signinTime-chatTime | where delta_sec >= 0 AND delta_sec <= 600 | convert ctime(chatTime) ctime(signinTime)
```

**Defender KQL:**
```kql
let WindowMin = 10m;
let ExternalChats = CloudAppEvents
    | where Timestamp > ago(7d)
    | where Application =~ "Microsoft Teams"
    | where ActionType in~ ("ChatCreated", "MessageSent")
    | where AccountType =~ "Guest" or RawEventData has "HasForeignTenantUsers" or AdditionalFields has "ExternalUser"
    | extend RecipientUpn = tolower(tostring(ObjectId)), ExternalSender = AccountDisplayName, ChatTime = Timestamp
    | project ChatTime, RecipientUpn, ExternalSender, ExternalSenderIP = IPAddress;
ExternalChats
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | where AuthenticationRequirement =~ "multiFactorAuthentication"
    | extend AuthDetails = tostring(AuthenticationDetails)
    | where AuthDetails has "succeeded" and (AuthDetails has "Authenticator" or AuthDetails has "Mobile app notification" or AuthDetails has "push")
    | project SignInTime = Timestamp, AccountUpn = tolower(AccountUpn), IPAddress, Country, Application, AppDisplayName, RiskLevelDuringSignIn
) on $left.RecipientUpn == $right.AccountUpn
| where SignInTime between (ChatTime .. ChatTime + WindowMin)
| extend DelaySeconds = datetime_diff('second', SignInTime, ChatTime)
| project ChatTime, SignInTime, DelaySeconds, RecipientUpn, ExternalSender, ExternalSenderIP, SignInIP = IPAddress, Country, AppDisplayName, RiskLevelDuringSignIn
| order by ChatTime desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `ommicrosoft.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
