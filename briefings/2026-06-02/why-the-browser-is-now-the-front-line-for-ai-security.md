# [CRIT] Why the browser is now the front line for AI security

**Source:** BleepingComputer
**Published:** 2026-06-02
**Article:** https://www.bleepingcomputer.com/news/security/why-the-browser-is-now-the-front-line-for-ai-security/

## Threat Profile

Why the browser is now the front line for AI security 
Sponsored by Push Security 
June 2, 2026
10:30 AM
0 
Security teams are staring at two AI problems at once. Adversaries are using AI to iterate on phishing kits, generate lures, and rotate infrastructure faster than blocklists can follow. Employees are adopting AI tools faster than security teams can review them, pasting sensitive data into LLMs, granting OAuth permissions to AI agents, and installing AI browser extensions that nobody vetted…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `openew.app`
- **SHA256:** `de8c50e8ccd240ef9d10ec26c26eeb37a4d1cad7c1e0edf3bb6e5689ec2dde78`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1583.008** — Acquire Infrastructure: Malvertising
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1098.003** — Account Manipulation: Additional Cloud Roles

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] OAuth device-code flow sign-in to Entra ID (device code phishing — Doko/ShinyHunters/BlackFile PhaaS)

`UC_12_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src values(Authentication.app) as app values(Authentication.signature) as auth_protocol from datamodel=Authentication where (Authentication.signature="deviceCode" OR Authentication.authentication_method="deviceCode" OR Authentication.action="success" AND Authentication.app="Microsoft Authentication Broker") by Authentication.user Authentication.dest Authentication.src_ip | `drop_dm_object_name(Authentication)` | where user!="" AND user!="-" | eval suspicious=if(match(src_ip,"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)"),0,1) | where suspicious=1 | sort 0 - firstTime
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| where AuthenticationProcessingDetails has "deviceCode" or AdditionalFields has "deviceCode" or AuthenticationDetails has "deviceCode"
| extend ParsedProcessing = tostring(AuthenticationProcessingDetails)
| project Timestamp, AccountUpn, AccountObjectId, IPAddress, Country, City, Application, ApplicationId, ResourceDisplayName, Browser, UserAgent, ClientAppUsed, ConditionalAccessStatus, RiskLevelDuringSignIn, IsInteractive, AuthenticationRequirement, ParsedProcessing
| order by Timestamp desc
```

### [LLM] LLMShare — malicious chatgpt.com/share/* link followed by browser-spawned LOLBin

`UC_12_10` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where (Web.url="*chatgpt.com/share/*" OR Web.url="*chat.openai.com/share/*") by Web.user Web.src Web.url _time | `drop_dm_object_name(Web)` | rename _time as click_time | join type=inner user [| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","arc.exe")) AND (Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","curl.exe","certutil.exe","bitsadmin.exe")) by Processes.user Processes.dest Processes.parent_process_name Processes.process_name Processes.process _time | `drop_dm_object_name(Processes)` | rename _time as exec_time user as user] | eval delay=exec_time-click_time | where delay >= 0 AND delay <= 60 | table click_time exec_time delay user src dest url parent_process_name process_name process
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowSeconds = 60;
let ShareVisits = DeviceNetworkEvents
    | where Timestamp > ago(LookbackDays)
    | where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","arc.exe","opera.exe")
    | where RemoteUrl has "chatgpt.com/share/" or RemoteUrl has "chat.openai.com/share/"
    | project ShareTime = Timestamp, DeviceId, DeviceName, AccountUpn = InitiatingProcessAccountUpn, BrowserExe = InitiatingProcessFileName, ShareUrl = RemoteUrl;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","arc.exe","opera.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe","regsvr32.exe","curl.exe","certutil.exe","bitsadmin.exe","msiexec.exe")
| join kind=inner ShareVisits on DeviceId
| where Timestamp between (ShareTime .. ShareTime + WindowSeconds * 1s)
| extend DelaySec = datetime_diff('second', Timestamp, ShareTime)
| project ShareTime, ProcTime = Timestamp, DelaySec, DeviceName, AccountUpn, BrowserExe, ShareUrl, FileName, ProcessCommandLine, SHA256
| order by ShareTime desc
```

### [LLM] Anomalous OAuth consent grant to AI / third-party SaaS application (Vercel/Salesloft pattern)

`UC_12_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime values(All_Changes.user) as user values(All_Changes.src) as src values(All_Changes.object) as target_app values(All_Changes.result) as result from datamodel=Change.Account_Management where All_Changes.action="consent" OR All_Changes.command IN ("Consent to application","Add OAuth2PermissionGrant","Add delegated permission grant","Add app role assignment grant to user") by All_Changes.object_id All_Changes.object_category | `drop_dm_object_name(All_Changes)` | eval is_ai_or_supplychain=if(match(target_app,"(?i)(chatgpt|openai|claude|anthropic|gemini|copilot|perplexity|mistral|llama|drift|salesloft|gainsight|mcp|model\s*context|agent)"),1,0) | where is_ai_or_supplychain=1 | sort 0 - firstTime
```

**Defender KQL:**
```kql
let SuspiciousAppPattern = @"(?i)(chatgpt|openai|claude|anthropic|gemini|copilot|perplexity|mistral|llama|drift|salesloft|gainsight|mcp|agent|model[ _]context)";
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in~ ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.","Add app role assignment grant to user.","Add service principal.","Add service principal credentials.")
| extend Raw = tostring(RawEventData)
| extend AppName = tostring(parse_json(Raw).Target[0].Name)
| extend AppId = tostring(parse_json(Raw).Target[0].ID)
| extend Scopes = tostring(parse_json(Raw).ModifiedProperties)
| extend InitiatorIp = tostring(parse_json(Raw).ActorIpAddress)
| where AppName matches regex SuspiciousAppPattern or Scopes matches regex SuspiciousAppPattern
| project Timestamp, AccountDisplayName, AccountObjectId, AccountType, IsAdminOperation, IPAddress, InitiatorIp, AppName, AppId, ActionType, Scopes, UserAgent
| order by Timestamp desc
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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
  - IP / domain IOC(s): `openew.app`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `de8c50e8ccd240ef9d10ec26c26eeb37a4d1cad7c1e0edf3bb6e5689ec2dde78`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
