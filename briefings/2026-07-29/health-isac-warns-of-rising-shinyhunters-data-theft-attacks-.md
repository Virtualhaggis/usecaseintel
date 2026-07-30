# [HIGH] Health-ISAC warns of rising ShinyHunters data theft attacks on healthcare

**Source:** BleepingComputer
**Published:** 2026-07-29
**Article:** https://www.bleepingcomputer.com/news/security/health-isac-warns-of-rising-shinyhunters-data-theft-attacks-on-healthcare/

## Threat Profile

Health-ISAC warns of rising ShinyHunters data theft attacks on healthcare 
By Lawrence Abrams 
July 29, 2026
01:54 PM
0 
Health-ISAC, a cybersecurity information-sharing organization for the health sector, is warning healthcare and medical technology organizations of an observed increase in successful attacks by ShinyHunters.
ShinyHunters is an extortion gang that primarily conducts supply chain and identity attacks to breach cloud SaaS and storage platforms in data theft attacks,
Over the past …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1566.004** — Phishing: Spearphishing Voice
- **T1098.005** — Account Manipulation: Device Registration
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1213.002** — Data from Information Repositories: SharePoint
- **T1530** — Data from Cloud Storage
- **T1567** — Exfiltration Over Web Service
- **T1538** — Cloud Service Dashboard

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Entra helpdesk password reset immediately followed by new MFA method registration (ShinyHunters ATO)

`UC_3_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as reg_time from datamodel=Change where nodename=All_Changes All_Changes.command IN ("User registered security info","Admin registered security info","User registered all required security info") by All_Changes.user | rename All_Changes.user as user | join type=inner user [ | tstats `summariesonly` max(_time) as reset_time from datamodel=Change where nodename=All_Changes All_Changes.command IN ("Reset password (by admin)","Reset user password","Change user password") by All_Changes.user | rename All_Changes.user as user ] | where reg_time>=reset_time AND reg_time<=reset_time+1800 | eval mins_after_reset=round((reg_time-reset_time)/60,1) | table user reset_time reg_time mins_after_reset | sort - reg_time
```

### New attacker device registered/joined to Microsoft Entra ID

`UC_3_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as first_seen max(_time) as last_seen values(All_Changes.src) as src from datamodel=Change where nodename=All_Changes All_Changes.command IN ("Add registered device","Register device","Add device") by All_Changes.user All_Changes.object | rename All_Changes.user as actor All_Changes.object as device | sort - last_seen
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "Add registered device"
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, City, ISP, UserAgent, ObjectName, Application
| order by Timestamp desc
```

### Suspicious OAuth application consent granting broad scopes (ShinyHunters DataLoader-style persistence)

`UC_3_8` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(All_Changes.object) as app values(All_Changes.src) as src min(_time) as first_seen from datamodel=Change where nodename=All_Changes All_Changes.command IN ("Consent to application","Add delegated permission grant","Add app role assignment grant to user","Add OAuth2PermissionGrant") by All_Changes.user | rename All_Changes.user as actor | sort - first_seen
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType == "Consent to application"
| extend Raw = tostring(RawEventData)
| project Timestamp, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ObjectName, ActivityObjects, Raw
| where Raw has_any ("offline_access","ReadWrite.All","Mail.Read","Files.Read.All","Sites.Read.All","Directory.Read.All","full_access") or isempty(Raw)
| order by Timestamp desc
```

### Bulk M365 / SharePoint / OneDrive file download by a single identity (cloud data theft)

`UC_3_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
sourcetype=o365:management:activity (Operation="FileDownloaded" OR Operation="FileSyncDownloadedFull") (Workload="SharePoint" OR Workload="OneDrive")
| bin _time span=1h
| stats count as downloads dc(SourceFileName) as files values(ClientIP) as src by UserId _time
| where downloads>200
| sort - downloads
```

**Defender KQL:**
```kql
let Threshold = 200;   // 200 downloads/hr ~ P99 of interactive-user baseline
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileDownloaded","FileSyncDownloadedFull")
| summarize Downloads = count(), Files = dcount(ObjectName), IPs = make_set(IPAddress, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by AccountObjectId, AccountDisplayName, bin(Timestamp, 1h)
| where Downloads > Threshold
| order by Downloads desc
```

### SSO application-access burst — one identity authenticating to many distinct SaaS apps in a short window

`UC_3_10` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Authentication.app) as distinct_apps values(Authentication.app) as apps values(Authentication.src) as src from datamodel=Authentication where nodename=Authentication Authentication.action=success by Authentication.user _time span=1h
| rename Authentication.user as user
| where distinct_apps>=8
| sort - distinct_apps
```

**Defender KQL:**
```kql
let AppThreshold = 8;   // >=8 distinct SaaS apps/hr = SSO-dashboard springboard burst
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| summarize DistinctApps = dcount(Application), Apps = make_set(Application, 30),
            IPs = make_set(IPAddress, 10), Countries = make_set(Country, 10),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by AccountUpn, bin(Timestamp, 1h)
| where DistinctApps >= AppThreshold
| order by DistinctApps desc
```

### Beaconing — periodic outbound to small set of destinations

`UC_BEACONING` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, values(All_Traffic.dest_port) AS ports
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.action="allowed" AND All_Traffic.dest_category!="internal"
    by _time span=10s, All_Traffic.src, All_Traffic.dest
| `drop_dm_object_name(All_Traffic)`
| streamstats current=f last(_time) AS prev_time by src, dest
| eval delta = _time - prev_time
| stats avg(delta) AS avg_delta stdev(delta) AS sd_delta count by src, dest
| where count > 30 AND sd_delta < 5 AND avg_delta>=30 AND avg_delta<=600
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public" and ActionType == "ConnectionSuccess"
| project DeviceName, RemoteIP, RemotePort, Timestamp
| sort by DeviceName asc, RemoteIP asc, RemotePort asc, Timestamp asc
| extend prev_dev = prev(DeviceName, 1), prev_ip = prev(RemoteIP, 1),
         prev_port = prev(RemotePort, 1), prev_ts = prev(Timestamp, 1)
| where DeviceName == prev_dev and RemoteIP == prev_ip and RemotePort == prev_port
| extend delta_sec = datetime_diff('second', Timestamp, prev_ts)
| summarize conn_count = count(), avg_delta = avg(delta_sec), stdev_delta = stdev(delta_sec)
    by DeviceName, RemoteIP, RemotePort
| where conn_count > 30 and avg_delta between (30.0 .. 600.0) and stdev_delta < 5.0
| order by conn_count desc
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


## Why this matters

Severity classified as **HIGH** based on: 11 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
