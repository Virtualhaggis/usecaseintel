# [CRIT] Phishing service spoofs RingCentral to steal Microsoft 365 accounts

**Source:** BleepingComputer
**Published:** 2026-08-04
**Article:** https://www.bleepingcomputer.com/news/security/phishing-service-spoofs-ringcentral-to-steal-microsoft-365-accounts/

## Threat Profile

Phishing service spoofs RingCentral to steal Microsoft 365 accounts 
By Bill Toulas 
August 4, 2026
05:45 PM
0 
The Greatness phishing-as-a-service (PhaaS) platform has expanded from credential phishing to adversary-in-the-middle attacks and device-code phishing targeting Microsoft 365 accounts.
The platform has been active since at least mid-2022 , targeting Microsoft 365 users in the United States, Canada, the UK, Australia, and South Africa.
It evolved over the years and now targets multiple …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `38.248.95.214`
- **Domain (defanged):** `panel.securehubcloud.com`
- **Domain (defanged):** `aitomayu.com`

## MITRE ATT&CK Techniques

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
- **T1566.002** — Phishing: Spearphishing Link
- **T1656** — Impersonation
- **T1114.002** — Email Collection: Remote Email Collection
- **T1621** — Multi-Factor Authentication Request Generation
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1539** — Steal Web Session Cookie
- **T1526** — Cloud Service Discovery
- **T1213** — Data from Information Repositories
- **T1087.004** — Account Discovery: Cloud Account
- **T1557** — Adversary-in-the-Middle

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Spoofed RingCentral email delivered to inbox despite SPF/DMARC failure (whitelist abuse)

`UC_40_6` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection == "Inbound"
| where SenderFromDomain =~ "ringcentral.com" or SenderFromAddress =~ "service@ringcentral.com" or SenderDisplayName has "RingCentral"
// header From claims RingCentral but envelope/auth does not match (IONOS-origin, no DKIM)
| where SenderMailFromDomain !~ "ringcentral.com"
| where DeliveryAction == "Delivered" and DeliveryLocation == "Inbox"
| extend Auth = tostring(AuthenticationDetails)
| where Auth has "fail" or Auth has "softfail" or Auth has "none"   // SPF/DMARC fail or DKIM none
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromAddress, SenderMailFromDomain, SenderIPv4, RecipientEmailAddress, Subject, DeliveryAction, DeliveryLocation, AuthenticationDetails
| order by Timestamp desc
```

### Microsoft 365 device-code authorization grant redeemed (Greatness device-code phishing)

`UC_40_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where ErrorCode == 0
| where AuthenticationProcessingDetails has "Device Code" or AuthenticationProcessingDetails has "deviceCode"
| project Timestamp, AccountUpn, AppDisplayName, ResourceDisplayName, IPAddress, Country, City, ClientAppUsed, IsInteractive, ConditionalAccessStatus, UserAgent
| order by Timestamp desc
```

### M365 token replay / sign-in from Greatness IOC IP and VPS/VPN hosting ASNs

`UC_40_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(30d)
| where ErrorCode == 0
| where IPAddress == "38.248.95.214"
| project Timestamp, AccountUpn, IPAddress, Country, City, Application, ResourceDisplayName, IsInteractive, ClientAppUsed, UserAgent, ConditionalAccessStatus
| order by Timestamp desc
```

### Bulk Microsoft Graph / M365 workload enumeration in a single session (post-compromise discovery)

`UC_40_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application in ("Microsoft Graph","Microsoft Exchange Online","Microsoft SharePoint Online","Microsoft OneDrive for Business","Microsoft Teams")
| where isnotempty(AccountObjectId) and AccountType == "Regular"
| summarize Workloads = dcount(Application), AppSet = make_set(Application), ActionSet = make_set(ActionType, 30), Events = count(), IPs = make_set(IPAddress, 10), ISPs = make_set(ISP, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountObjectId, AccountDisplayName, bin(Timestamp, 1h)
| where Workloads >= 4   // Exchange + SharePoint + OneDrive + Teams touched within 1h = Graph recon fan-out
| extend HasGreatnessIP = IPs has "38.248.95.214"
| order by Workloads desc
```

### Endpoint/proxy connections to Greatness AiTM phishing infrastructure

`UC_40_10` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("aitomayu.com","panel.securehubcloud.com") or RemoteIP == "38.248.95.214"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine
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
  - IP / domain IOC(s): `38.248.95.214`, `panel.securehubcloud.com`, `aitomayu.com`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
