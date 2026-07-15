# [CRIT] New phishing kits target Microsoft 365 accounts, evade MFA

**Source:** BleepingComputer
**Published:** 2026-07-14
**Article:** https://www.bleepingcomputer.com/news/security/new-phishing-kits-target-microsoft-365-accounts-evade-mfa/

## Threat Profile

New phishing kits target Microsoft 365 accounts, evade MFA 
By Bill Toulas 
July 14, 2026
08:49 AM
0 
Two new phishing kits, Jalisco and OmegaLord, have been discovered in attacks targeting Microsoft 365 accounts, using techniques that defeat multi-factor authentication (MFA).
While Jalisco uses the device-code phishing method, OmegaLord masquerades as a PDF reader to collect account login credentials and associated phone numbers, which could help the attacker intercept or hijack MFA requests or…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `authplanned.online`
- **Domain (defanged):** `grantfundingapplications.com`
- **Domain (defanged):** `sessionopen0.site`
- **Domain (defanged):** `levaquin2us.top`
- **Domain (defanged):** `nuclear-rose-7ci1cmml-dpoaxo1bhyxi.edgeone.app`
- **Domain (defanged):** `pebr-gl6z-0vzu-434xz.b-cdn.net`
- **Domain (defanged):** `secure-folder-9f8a2983fbf5479e8d8c267e0df4e73d.3vvcompany.com`
- **Domain (defanged):** `116ec3a1ad128d7d.darkwebf.workers.dev`
- **Domain (defanged):** `wingboard.b-cdn.net`

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
- **T1071** — Application Layer Protocol
- **T1566** — Phishing
- **T1098.005** — Account Manipulation: Device Registration
- **T1213.002** — Data from Information Repositories: SharePoint
- **T1530** — Data from Cloud Storage

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Successful Entra ID sign-in via OAuth 2.0 device code flow (Jalisco/EvilTokens device-code phishing)

`UC_28_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.action="success" Authentication.signature="*device*code*" by Authentication.user Authentication.src Authentication.app Authentication.signature
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0                                   // successful auth only
| where AuthenticationProcessingDetails has "Device Code" // OAuth 2.0 device authorization grant flow
| where AccountUpn !endswith "$"
| project Timestamp, AccountUpn, AccountDisplayName, Application, AppDisplayName,
          ResourceDisplayName, IPAddress, Country, City, ClientAppUsed, UserAgent, DeviceTrustType
| order by Timestamp desc
```

### Multiple rogue Entra device registrations named 'Microsoft'/'Windows' on one account

`UC_28_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(All_Changes.object) as devices dc(All_Changes.object) as device_count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where All_Changes.action="created" All_Changes.object_category="device" (All_Changes.object="*Microsoft*" OR All_Changes.object="*Windows*") by All_Changes.user _time span=1h
| `drop_dm_object_name(All_Changes)`
| where device_count >= 2
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(3d)
| where ActionType in ("Add device","Add registered owner to device","Add registered users to device")
| where ObjectName has "Microsoft" or ObjectName has "Windows"   // benign-sounding rogue device names
| summarize DeviceCount = dcount(ObjectName), Devices = make_set(ObjectName, 20),
            IPs = make_set(IPAddress, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
          by AccountObjectId, AccountDisplayName, bin(Timestamp, 1h)
| where DeviceCount >= 2   // Entra default limit is 50; ReliaQuest recommends 1-2. Attackers registered up to 5.
| order by LastSeen desc
```

### Rapid bulk SharePoint/OneDrive download by a single account (device-code extortion exfil, ~6 min)

`UC_28_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`o365_management_activity` (Workload=SharePoint OR Workload=OneDrive) Operation IN ("FileDownloaded","FileSyncDownloadedFull","FileAccessed")
| bin _time span=6m
| stats dc(ObjectId) as FileCount values(SourceFileName) as Files values(ClientIP) as ClientIPs min(_time) as firstTime max(_time) as lastTime by UserId _time
| where FileCount >= 50
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(3d)
| where Application in ("Microsoft SharePoint Online","Microsoft OneDrive for Business")
| where ActionType in ("FileDownloaded","FileSyncDownloadedFull","FileAccessed")
| summarize FileCount = dcount(ObjectName), Files = make_set(ObjectName, 50), IPs = make_set(IPAddress, 10),
            StartTime = min(Timestamp), EndTime = max(Timestamp)
          by AccountObjectId, AccountDisplayName, bin(Timestamp, 6m)
| extend WindowSeconds = datetime_diff('second', EndTime, StartTime)
| where FileCount >= 50   // bulk pull; ReliaQuest observed full exfil in ~6 minutes post-compromise
| order by EndTime desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `authplanned.online`, `grantfundingapplications.com`, `sessionopen0.site`, `levaquin2us.top`, `nuclear-rose-7ci1cmml-dpoaxo1bhyxi.edgeone.app`, `pebr-gl6z-0vzu-434xz.b-cdn.net`, `secure-folder-9f8a2983fbf5479e8d8c267e0df4e73d.3vvcompany.com`, `116ec3a1ad128d7d.darkwebf.workers.dev` _(+1 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
