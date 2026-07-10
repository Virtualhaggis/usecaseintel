# [HIGH] New Helix vishing group emerges in SharePoint data theft attacks

**Source:** BleepingComputer
**Published:** 2026-07-09
**Article:** https://www.bleepingcomputer.com/news/security/new-helix-vishing-group-emerges-in-sharepoint-data-theft-attacks/

## Threat Profile

New Helix vishing group emerges in SharePoint data theft attacks 
By Bill Toulas 
July 9, 2026
01:08 PM
0 
A new data-extortion group called Helix is using identity-focused tactics such as voice phishing (vishing), device code phishing, and multi-factor authentication (MFA) abuse to steal data from SharePoint environments.
Initial contact is made through vishing. In some cases, the threat actor called employees while impersonating their manager, using either the manager's name or caller ID spoof…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `179.43.185.230`
- **IPv4 (defanged):** `179.43.185.226`
- **IPv4 (defanged):** `179.43.171.42`
- **Domain (defanged):** `oskeysync.com`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1071** — Application Layer Protocol
- **T1528** — Steal Application Access Token
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1621** — Multi-Factor Authentication Request Generation
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1098.005** — Account Manipulation: Device Registration
- **T1213.002** — Data from Information Repositories: SharePoint
- **T1083** — File and Directory Discovery
- **T1119** — Automated Collection
- **T1567.002** — Exfiltration to Cloud Storage
- **T1566.002** — Phishing: Spearphishing Link

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Entra ID device-code authentication success (Helix vishing entry vector)

`UC_19_4` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=o365 sourcetype="o365:management:activity" Workload=AzureActiveDirectory Operation=UserLoggedIn ResultStatus=Success
| search (ExtendedProperties{}.Name="authenticationProtocol" AND ExtendedProperties{}.Value="deviceCode") OR _raw="*deviceCode*"
| stats earliest(_time) as firstSeen latest(_time) as lastSeen count values(ClientIP) as src_ips values(UserAgent) as user_agents by UserId, ApplicationId
| sort - count
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(14d)
| where ErrorCode == 0
| where AuthenticationProcessingDetails has "Device Code"
| where isnotempty(AccountUpn) and AccountUpn !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), SignIns=count(), IPs=make_set(IPAddress,10), Cities=make_set(City,5), Apps=make_set(Application,5) by AccountUpn, Country
| order by FirstSeen desc
```

### New MFA method registered within 2h of a device-code sign-in (Helix persistence)

`UC_19_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=o365 sourcetype="o365:management:activity" Workload=AzureActiveDirectory (Operation="UserLoggedIn" AND _raw="*deviceCode*") OR Operation="User registered security info"
| eval evt=if(Operation="User registered security info","reg","devicecode")
| transaction UserId maxspan=2h startswith=eval(evt="devicecode") endswith=eval(evt="reg")
| where eventcount>1
| table _time UserId ClientIP UserAgent Operation
```

### Automated SharePoint enumeration via python-requests/2.28.1 from Helix IP

`UC_19_6` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=o365 sourcetype="o365:management:activity" Workload=SharePoint
| search UserAgent="python-requests/2.28.1" OR UserAgent="python-requests*" OR ClientIP IN ("179.43.185.230","179.43.185.226") OR _raw="*contentclass:STS_Site*"
| stats earliest(_time) as firstSeen latest(_time) as lastSeen count values(Operation) as ops dc(Site_Url) as sites by UserId, ClientIP, UserAgent
| sort - count
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "SharePoint"
| where UserAgent has "python-requests" or IPAddress in ("179.43.185.230","179.43.185.226")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Actions=make_set(ActionType,25), ActionCount=count(), Objects=dcount(ObjectName) by AccountObjectId, AccountDisplayName, IPAddress, UserAgent, ISP
| order by ActionCount desc
```

### Bulk SharePoint download spike from Helix python-requests client

`UC_19_7` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=o365 sourcetype="o365:management:activity" Workload=SharePoint Operation IN ("FileDownloaded","FileSyncDownloadedFull","FileAccessed")
| search UserAgent="python-requests*" OR ClientIP IN ("179.43.185.230","179.43.185.226")
| bucket _time span=1h
| stats count as downloads dc(SourceFileName) as distinct_files values(ClientIP) as ips by _time, UserId, UserAgent
| where downloads > 50
| sort - downloads
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where Application has "SharePoint" or Application has "OneDrive"
| where ActionType in~ ("FileDownloaded","FileSyncDownloadedFull","FileAccessed")
| where UserAgent has "python-requests" or IPAddress in ("179.43.185.230","179.43.185.226")
| summarize Downloads=count(), DistinctObjects=dcount(ObjectName), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by AccountObjectId, AccountDisplayName, IPAddress, UserAgent, bin(Timestamp, 1h)
| where Downloads > 50
| order by Downloads desc
```

### Endpoint contact to Helix device-code phishing domain oskeysync.com

`UC_19_8` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen from datamodel=Network_Resolution.DNS where DNS.query="*oskeysync.com" by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| sort - lastSeen
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "oskeysync.com"
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `179.43.185.230`, `179.43.185.226`, `179.43.171.42`, `oskeysync.com`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
