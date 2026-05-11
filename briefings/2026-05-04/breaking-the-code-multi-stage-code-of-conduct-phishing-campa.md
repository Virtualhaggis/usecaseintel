# [CRIT] Breaking the code: Multi-stage ‘code of conduct’ phishing campaign leads to AiTM token compromise

**Source:** Microsoft Security Blog
**Published:** 2026-05-04
**Article:** https://www.microsoft.com/en-us/security/blog/2026/05/04/breaking-the-code-multi-stage-code-of-conduct-phishing-campaign-leads-to-aitm-token-compromise/

## Threat Profile

Tags 
Adversary-in-the-middle (AiTM) 
Credential theft 
Phishing 
Content types 
Research 
Products and services 
Microsoft Defender 
Microsoft Defender for Endpoint 
Microsoft Defender for Office 365 
Topics 
Actionable threat insights 
Threat intelligence 
Phishing campaigns continue to improve sophistication and refinement in blending social engineering, delivery and hosting infrastructure, and authentication abuse to remain effective against evolving security controls. A large-scale credenti…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-31431`
- **Domain (defanged):** `acceptable-use-policy-calendly.de`
- **Domain (defanged):** `compliance-protectionoutlook.de`
- **Domain (defanged):** `cocinternal.com`
- **Domain (defanged):** `gadellinet.com`
- **Domain (defanged):** `harteprn.com`
- **SHA256:** `5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6`
- **SHA256:** `B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD`
- **SHA256:** `11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D`

## MITRE ATT&CK Techniques

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1566.002** — Phishing: Spearphishing Link
- **T1557** — Adversary-in-the-Middle
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Code-of-Conduct AiTM phishing — inbound email from named sender addresses/domains

`UC_86_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where Email.src_user="*@*" by Email.recipient Email.src_user Email.subject Email.message_id Email.file_name
| `drop_dm_object_name(Email)`
| where match(src_user, "(?i)^(cocpostmaster@cocinternal\.com|nationaladmin@gadellinet\.com|nationalintegrity@harteprn\.com|m365premiumcommunications@cocinternal\.com|documentviewer@na\.businesshellosign\.de)$") OR match(src_user, "(?i)@(cocinternal\.com|gadellinet\.com|harteprn\.com|na\.businesshellosign\.de)$")
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime recipient src_user subject file_name message_id count
```

**Defender KQL:**
```kql
let _campaign_senders = dynamic(["cocpostmaster@cocinternal.com","nationaladmin@gadellinet.com","nationalintegrity@harteprn.com","m365premiumcommunications@cocinternal.com","documentviewer@na.businesshellosign.de"]);
let _campaign_domains = dynamic(["cocinternal.com","gadellinet.com","harteprn.com","na.businesshellosign.de"]);
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where SenderMailFromAddress in~ (_campaign_senders)
   or SenderFromAddress in~ (_campaign_senders)
   or SenderMailFromDomain in~ (_campaign_domains)
   or SenderFromDomain in~ (_campaign_domains)
| project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, AttachmentCount, UrlCount, ThreatTypes
| order by Timestamp desc
```

### [LLM] Code-of-Conduct campaign PDF attachment by SHA256 / filename pattern

`UC_86_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where Email.file_hash IN ("5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6","B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD","11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D") OR Email.file_name="Awareness Case Log File*April 2026.pdf" OR Email.file_name="Disciplinary Action*Employee Device Handling Case.pdf" by Email.recipient Email.src_user Email.file_name Email.file_hash Email.message_id Email.subject
| `drop_dm_object_name(Email)`
| append [
  | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6","B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD","11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D") OR Filesystem.file_name="Awareness Case Log File*April 2026.pdf" OR Filesystem.file_name="Disciplinary Action*Employee Device Handling Case.pdf" by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_hash Filesystem.file_path
  | `drop_dm_object_name(Filesystem)`
]
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _campaign_pdf_hashes = dynamic([
  "5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6",
  "B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD",
  "11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D"]);
union isfuzzy=true
  ( EmailAttachmentInfo
    | where Timestamp > ago(30d)
    | where SHA256 in~ (_campaign_pdf_hashes)
       or FileName matches regex @"(?i)^Awareness Case Log File\s*[-–]\s*\w+\s+\d{1,2}(st|nd|rd|th)?,?\s*April\s*2026\.pdf$"
       or FileName =~ "Disciplinary Action - Employee Device Handling Case.pdf"
    | project Timestamp, Source = "Email", NetworkMessageId, SenderFromAddress, RecipientEmailAddress, FileName, SHA256, FileSize, MalwareFilterVerdict ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in~ (_campaign_pdf_hashes)
       or FileName matches regex @"(?i)^Awareness Case Log File\s*[-–]\s*\w+\s+\d{1,2}(st|nd|rd|th)?,?\s*April\s*2026\.pdf$"
       or FileName =~ "Disciplinary Action - Employee Device Handling Case.pdf"
    | project Timestamp, Source = "Endpoint", DeviceName, InitiatingProcessAccountUpn, FileName, FolderPath, SHA256, InitiatingProcessFileName )
| order by Timestamp desc
```

### [LLM] AiTM landing domain access followed by Microsoft sign-in within 10 min

`UC_86_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*acceptable-use-policy-calendly.de*" OR Web.url="*compliance-protectionoutlook.de*" OR Web.dest="acceptable-use-policy-calendly.de" OR Web.dest="compliance-protectionoutlook.de") by Web.user Web.src Web.dest Web.url _time span=1s
| `drop_dm_object_name(Web)`
| rename _time as click_time, user as victim_user
| join type=inner victim_user [
  | tstats `summariesonly` count from datamodel=Authentication where Authentication.action=success Authentication.app="*Microsoft*" by Authentication.user Authentication.src Authentication.app _time span=1s
  | `drop_dm_object_name(Authentication)`
  | rename _time as auth_time, user as victim_user, src as auth_src
]
| where auth_time >= click_time AND auth_time <= click_time + 600
| eval delay_sec = auth_time - click_time
| table click_time auth_time delay_sec victim_user src dest url auth_src app
```

**Defender KQL:**
```kql
let _aitm_domains = dynamic(["acceptable-use-policy-calendly.de","compliance-protectionoutlook.de"]);
let _window = 10m;
let ClickEvents =
  union isfuzzy=true
    ( UrlClickEvents
      | where Timestamp > ago(7d)
      | where ActionType in ("ClickAllowed","ClickedThrough")
      | where Url has_any (_aitm_domains)
      | project ClickTime = Timestamp, AccountUpn, ClickIP = IPAddress, ClickUrl = Url ),
    ( DeviceNetworkEvents
      | where Timestamp > ago(7d)
      | where RemoteUrl has_any (_aitm_domains)
      | project ClickTime = Timestamp, AccountUpn = InitiatingProcessAccountUpn, DeviceName, ClickIP = LocalIP, ClickUrl = RemoteUrl );
ClickEvents
| where isnotempty(AccountUpn)
| join kind=inner (
    AADSignInEventsBeta
    | where Timestamp > ago(7d)
    | where ErrorCode == 0
    | where IsInteractive == true
    | project SignInTime = Timestamp, AccountUpn, SignInIP = IPAddress, Country, Application, AppDisplayName, RiskLevelDuringSignIn, ConditionalAccessStatus
  ) on AccountUpn
| where SignInTime between (ClickTime .. ClickTime + _window)
| extend DelaySec = datetime_diff('second', SignInTime, ClickTime)
| project ClickTime, SignInTime, DelaySec, AccountUpn, ClickUrl, ClickIP, SignInIP, Country, Application, AppDisplayName, RiskLevelDuringSignIn, ConditionalAccessStatus
| order by ClickTime desc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-31431`

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `acceptable-use-policy-calendly.de`, `compliance-protectionoutlook.de`, `cocinternal.com`, `gadellinet.com`, `harteprn.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `5DB1ECBBB2C90C51D81BDA138D4300B90EA5EB2885CCE1BD921D692214AECBC6`, `B5A3346082AC566B4494E6175F1CD9873B64ABE6C902DB49BD4E8088876C9EAD`, `11420D6D693BF8B19195E6B98FEDD03B9BCBC770B6988BC64CB788BFABE1A49D`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 13 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
