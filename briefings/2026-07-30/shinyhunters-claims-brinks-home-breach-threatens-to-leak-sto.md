# [HIGH] ShinyHunters claims Brinks Home breach, threatens to leak stolen data

**Source:** BleepingComputer
**Published:** 2026-07-30
**Article:** https://www.bleepingcomputer.com/news/security/shinyhunters-claims-brinks-home-breach-threatens-to-leak-stolen-data/

## Threat Profile

ShinyHunters claims Brinks Home breach, threatens to leak stolen data 
By Ionut Ilascu 
July 30, 2026
12:46 PM
0 
Residential security company Brinks Home has disclosed that hackers breached some of its systems and are threatening to leak allegedly stolen data.
​The company identified the attack on July 20 and immediately activated its incident response procedure to contain the breach.
William Niles, CEO at Brinks Home, said that the company’s team was working with “leading forensics experts to …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `brinkshome.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1071** — Application Layer Protocol
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration
- **T1566.004** — Phishing: Spearphishing Voice
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1528** — Steal Application Access Token
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Entra MFA/security-info registration fan-out from single source IP (ShinyHunters help-desk vishing)

`UC_38_4` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(All_Changes.object) as DistinctUsers values(All_Changes.object) as TargetUsers min(_time) as firstTime max(_time) as lastTime from datamodel=Change.All_Changes where All_Changes.object_category=user All_Changes.action=modified (All_Changes.command="User registered security info" OR All_Changes.command="User started security info registration" OR All_Changes.command="Admin registered security info" OR All_Changes.command="User registered all required security info") by All_Changes.src _time span=10m
| `drop_dm_object_name(All_Changes)`
| where DistinctUsers>=3
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - DistinctUsers
```

**Defender KQL:**
```kql
let window = 10m;
CloudAppEvents
| where Timestamp > ago(7d)
| where Application in ("Microsoft Entra ID","Office 365","Azure Active Directory")
| where ActionType in ("User registered security info.","User started security info registration.","Admin registered security info.","User registered all required security info.")
| where isnotempty(IPAddress)
| summarize DistinctUsers = dcount(AccountObjectId), Users = make_set(AccountDisplayName, 20), Ops = make_set(ActionType), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by IPAddress, CountryCode, bin(Timestamp, window)
| where DistinctUsers >= 3   // 3+ distinct users enrolling MFA from one IP in 10m = help-desk vishing (ReliaQuest guidance)
| order by DistinctUsers desc
```

### Entra MFA method registered from an IP the user has never signed in from (attacker device enrollment)

`UC_38_5` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as firstTime from datamodel=Change.All_Changes where All_Changes.object_category=user All_Changes.action=modified (All_Changes.command="User registered security info" OR All_Changes.command="Admin registered security info" OR All_Changes.command="User changed default security info" OR All_Changes.command="User registered all required security info") by All_Changes.object All_Changes.src
| `drop_dm_object_name(All_Changes)`
| rename object as user, src as reg_src
| join type=left user [| tstats `summariesonly` values(Authentication.src) as known_src from datamodel=Authentication where Authentication.action=success earliest=-30d@d latest=-2d@d by Authentication.user | `drop_dm_object_name(Authentication)`]
| eval known_match=if(isnull(known_src),0,mvcount(mvfilter(known_src=reg_src)))
| where known_match=0
| `security_content_ctime(firstTime)`
| table firstTime user reg_src
```

**Defender KQL:**
```kql
let lookback = 30d;
let recent = 2d;
let knownIps = AADSignInEventsBeta
    | where Timestamp between (ago(lookback) .. ago(recent))
    | where ErrorCode == 0
    | summarize by AccountObjectId, IPAddress;
CloudAppEvents
| where Timestamp > ago(recent)
| where ActionType in ("User registered security info.","Admin registered security info.","User changed default security info.","User registered all required security info.","User started security info registration.")
| where isnotempty(IPAddress) and isnotempty(AccountObjectId)
| join kind=leftanti knownIps on AccountObjectId, IPAddress
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, City, ActionType, Application
| order by Timestamp desc
```

### Entra user OAuth consent to connected app (ShinyHunters Data Loader-style Salesforce grant)

`UC_38_6` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime values(All_Changes.object) as app values(All_Changes.object_attrs) as scopes from datamodel=Change.All_Changes where All_Changes.action=created (All_Changes.command="Consent to application" OR All_Changes.command="Add delegated permission grant" OR All_Changes.command="Add OAuth2PermissionGrant") by All_Changes.user All_Changes.src _time
| `drop_dm_object_name(All_Changes)`
| `security_content_ctime(firstTime)`
| sort - firstTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("Consent to application.","Add delegated permission grant.","Add OAuth2PermissionGrant.")
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ActionType, ObjectName, ActivityObjects, RawEventData
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `brinkshome.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 7 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
