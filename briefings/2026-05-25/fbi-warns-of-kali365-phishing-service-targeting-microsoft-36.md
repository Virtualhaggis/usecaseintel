# [CRIT] FBI warns of Kali365 phishing service targeting Microsoft 365 accounts

**Source:** BleepingComputer
**Published:** 2026-05-25
**Article:** https://www.bleepingcomputer.com/news/security/fbi-warns-of-kali365-phishing-service-targeting-microsoft-365-accounts/

## Threat Profile

FBI warns of Kali365 phishing service targeting Microsoft 365 accounts 
By Lawrence Abrams 
May 25, 2026
08:45 AM
0 
The FBI is warning about the Kali365 phishing-as-a-service platform (PhaaS) that is used to hijack Microsoft 365 accounts by abusing OAuth device code authentication to steal session tokens and bypass multi-factor authentication (MFA).
According to the FBI PSA , Kali365 first emerged in April 2026 and is distributed via Telegram channels for cybercriminals seeking an easier way to…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `216.203.20.95`
- **IPv4 (defanged):** `162.243.166.119`
- **IPv4 (defanged):** `199.91.220.111`
- **Domain (defanged):** `kali365.xyz`
- **Domain (defanged):** `v2.kali365.xyz`
- **Domain (defanged):** `api.kali365.xyz`
- **SHA256:** `883d5d4a73b0ac8cf4f78fe46d8f4e76e21508872836f2b439af2de4a205128e`
- **SHA256:** `09bb7e568e573497e22bfa3f36d71fe9d104899826608affedb25d988f391c85`
- **SHA256:** `2fa6fc2199d3be55e240500d87e4484f39b9315bf336be25434f6716b8d28ec8`

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
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1566** — Phishing
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1564.008** — Email Hiding Rules
- **T1114.001** — Local Email Collection
- **T1098.005** — Account Manipulation: Device Registration
- **T1557** — Adversary-in-the-Middle

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Microsoft 365 OAuth device code authentication flow (Kali365 token theft)

`UC_3_8` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
index=azure sourcetype="azure:aad:signin" "properties.authenticationProtocol"="deviceCode" "properties.status.errorCode"=0
| stats count min(_time) as firstTime max(_time) as lastTime values("properties.appDisplayName") as apps values(src_ip) as src_ips dc(src_ip) as ip_count by user
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
// Device code flow marker lives in AuthenticationProcessingDetails when the dedicated AuthenticationProtocol column is unavailable
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where ErrorCode == 0
| extend ProcDetails = tostring(AuthenticationProcessingDetails)
| where ProcDetails has "Device Code"
| summarize SignInCount = count(), Apps = make_set(Application), SrcIPs = make_set(IPAddress), Countries = make_set(Country), arg_max(Timestamp, *) by AccountUpn
| project Timestamp, AccountUpn, Application, IPAddress, Country, City, DeviceTrustType, SignInCount, Apps, SrcIPs, Countries
| order by Timestamp desc
```

### [LLM] Kali365 post-compromise mailbox hiding rule (spam/phish/click/link/SharePoint keywords)

`UC_3_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
index=o365 sourcetype="o365:management:activity" Operation IN ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| eval params=lower(_raw)
| where like(params,"%spam%") OR like(params,"%phish%") OR like(params,"%click%") OR like(params,"%link%") OR like(params,"%sharepoint%")
| where like(params,"%movetofolder%") OR like(params,"%markasread%") OR like(params,"%deletemessage%") OR like(params,"%junk%")
| table _time, UserId, ClientIP, Operation, Parameters
| sort - _time
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in~ ("New-InboxRule","Set-InboxRule","Update-InboxRules","UpdateInboxRules")
| extend Raw = tolower(tostring(RawEventData))
| where Raw has_any ("spam","phish","click","link","sharepoint")
| where Raw has_any ("movetofolder","markasread","deletemessage","junkemail")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, ActionType, ObjectName, RawEventData
| order by Timestamp desc
```

### [LLM] Attacker device registration in victim Entra tenant after device-code compromise

`UC_3_10` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
index=azure sourcetype="azure:aad:audit" operationName IN ("Add registered device","Register device","Add device") (resultType="success" OR result="success")
| table _time, operationName, initiatedBy, targetResources, result
| sort - _time
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "Entra" or Application has "Azure Active Directory"
| where ActionType has_any ("Add registered device","Register device","Add device","Add registered owner to device")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ActionType, ObjectName, ActivityObjects, RawEventData
| order by Timestamp desc
```

### [LLM] Microsoft 365 sign-in from Kali365 phishing infrastructure IPs

`UC_3_11` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.src IN ("216.203.20.95","162.243.166.119","199.91.220.111") by Authentication.user, Authentication.src, Authentication.app, Authentication.action
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
let KaliInfra = dynamic(["216.203.20.95","162.243.166.119","199.91.220.111"]);
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where IPAddress in (KaliInfra)
| project Timestamp, AccountUpn, Application, ApplicationId, IPAddress, Country, City, ErrorCode, DeviceTrustType, UserAgent
| order by Timestamp desc
```

### [LLM] Endpoint connection or DNS lookup to Kali365 Cookie Link AitM domains

`UC_3_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where DNS.query IN ("kali365.xyz","v2.kali365.xyz","api.kali365.xyz","duemineral.uk","*.kali365.xyz") by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
let KaliDomains = dynamic(["kali365.xyz","v2.kali365.xyz","api.kali365.xyz","duemineral.uk"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (KaliDomains)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName
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
  - IP / domain IOC(s): `216.203.20.95`, `162.243.166.119`, `199.91.220.111`, `kali365.xyz`, `v2.kali365.xyz`, `api.kali365.xyz`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `883d5d4a73b0ac8cf4f78fe46d8f4e76e21508872836f2b439af2de4a205128e`, `09bb7e568e573497e22bfa3f36d71fe9d104899826608affedb25d988f391c85`, `2fa6fc2199d3be55e240500d87e4484f39b9315bf336be25434f6716b8d28ec8`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 13 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
