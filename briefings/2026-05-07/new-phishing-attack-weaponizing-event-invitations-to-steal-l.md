# [CRIT] New Phishing Attack Weaponizing Event Invitations to Steal Login Credentials

**Source:** Cyber Security News
**Published:** 2026-05-07
**Article:** https://cybersecuritynews.com/new-phishing-attack-weaponizing-event-invitations/

## Threat Profile

Home Cyber Security News 
New Phishing Attack Weaponizing Event Invitations to Steal Login Credentials 
By Tushar Subhra Dutta 
May 7, 2026 
A large-scale phishing campaign has been quietly targeting organizations across the United States, using fake event invitations as bait. Rather than sending a suspicious attachment or an obvious scam link, attackers lure victims with what appears to be a legitimate party or gathering invitation. 
Once clicked, those links lead to pages designed to steal log…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `festiveparty.us`
- **Domain (defanged):** `getceptionparty.de`
- **Domain (defanged):** `celebratieinvitiee.de`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1566.002** — Phishing: Spearphishing Link
- **T1583.001** — Acquire Infrastructure: Domains
- **T1056.003** — Input Capture: Web Portal Capture
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Event-invitation phishing kit URL signature: /blocked.html + /Image/<brand>.png chain

`UC_8_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.site) as sites FROM datamodel=Web WHERE (Web.url="*/blocked.html" OR Web.url="*/Image/office360.png" OR Web.url="*/Image/office.png" OR Web.url="*/Image/yahoo.png" OR Web.url="*/Image/google.png" OR Web.url="*/Image/aol.png" OR Web.url="*/Image/email.png") BY Web.src Web.user _time span=10m | `drop_dm_object_name(Web)` | eval url_str=mvjoin(urls,"|") | where match(url_str,"/blocked\.html") AND match(url_str,"/Image/(office360|office|yahoo|google|aol|email)\.png") | search NOT sites IN ("*.microsoft.com","*.google.com","*.yahoo.com","*.aol.com") | convert ctime(firstTime) ctime(lastTime) | table firstTime, lastTime, src, user, sites, urls
```

**Defender KQL:**
```kql
let Window = 10m;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any ("/blocked.html","/Image/office360.png","/Image/office.png","/Image/yahoo.png","/Image/google.png","/Image/aol.png","/Image/email.png")
| extend Bucket = bin(Timestamp, Window),
         Domain = tolower(extract(@"https?://([^/]+)/", 1, RemoteUrl))
| summarize
    HasBlocked  = countif(RemoteUrl has "/blocked.html"),
    HasBrandImg = countif(RemoteUrl has_any ("/Image/office360.png","/Image/office.png","/Image/yahoo.png","/Image/google.png","/Image/aol.png","/Image/email.png")),
    UrlSamples  = make_set(RemoteUrl, 25),
    Domains     = make_set(Domain, 5),
    FirstSeen   = min(Timestamp),
    LastSeen    = max(Timestamp)
    by DeviceId, DeviceName, InitiatingProcessFileName, Bucket
| where HasBlocked >= 1 and HasBrandImg >= 1   // both halves of the campaign request chain in one window
| where not(Domains has_any ("microsoft.com","google.com","yahoo.com","aol.com","office.com"))
| project FirstSeen, LastSeen, DeviceName, InitiatingProcessFileName, Domains, UrlSamples
| order by FirstSeen desc
```

### [LLM] Phishing kit visitor-ID exfil to /check_telegram_updates.php

`UC_8_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user) as user values(Web.http_method) as method FROM datamodel=Web WHERE (Web.url="*/check_telegram_updates.php*" OR (Web.url="*/pass.php*" AND Web.url="*/mlog.php*")) BY Web.src Web.site | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | table firstTime, lastTime, src, site, user, urls, method
```

**Defender KQL:**
```kql
let Window = 10m;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any ("/check_telegram_updates.php","/pass.php","/mlog.php","/processmail.php","/process.php")
| extend Domain = tolower(extract(@"https?://([^/]+)/", 1, RemoteUrl)), Bucket = bin(Timestamp, Window)
| summarize
    HasTelegramExfil = countif(RemoteUrl has "/check_telegram_updates.php"),
    HasGoogleFlow    = countif(RemoteUrl has "/pass.php") + countif(RemoteUrl has "/mlog.php"),
    HasGenericCred   = countif(RemoteUrl has "/processmail.php") + countif(RemoteUrl has "/process.php"),
    UrlSamples       = make_set(RemoteUrl, 25),
    FirstSeen        = min(Timestamp),
    LastSeen         = max(Timestamp)
    by DeviceId, DeviceName, AccountName, InitiatingProcessFileName, Domain, Bucket
// /check_telegram_updates.php alone is unique enough; pass.php+mlog.php co-occurrence is the Google-flow signature
| where HasTelegramExfil > 0 or HasGoogleFlow >= 2 or (HasGenericCred >= 2 and HasGoogleFlow > 0)
| project FirstSeen, LastSeen, DeviceName, AccountName, InitiatingProcessFileName, Domain, UrlSamples, HasTelegramExfil, HasGoogleFlow, HasGenericCred
| order by FirstSeen desc
```

### [LLM] RMM installer (ScreenConnect/ConnectWise/ITarian/Datto/LogMeIn) drop within 30m of phishing-kit visit

`UC_8_11` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as proc_time values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user FROM datamodel=Endpoint.Processes WHERE (Processes.process_name IN ("ScreenConnect.ClientSetup.exe","ScreenConnect.exe","ITarianClient.exe","ITSMAgent.exe","ConnectWiseControl.ClientSetup.exe","ConnectWiseControl.exe","LMI_Rescue.exe","Rescue.exe","LMI-Rescue-Calling-Card.exe","DattoRMMAgent.exe","AgentSetup_Default.exe","atrmm.exe","Aem.exe")) AND (Processes.parent_process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","outlook.exe","explorer.exe","msiexec.exe")) BY Processes.dest Processes.process_name | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats summariesonly=true min(_time) as visit_time values(Web.url) as visited_url FROM datamodel=Web WHERE (Web.url="*/blocked.html" OR Web.url="*/Image/office360.png" OR Web.url="*/Image/office.png" OR Web.url="*/Image/yahoo.png" OR Web.url="*/Image/google.png" OR Web.url="*/Image/aol.png" OR Web.url="*/Image/email.png" OR Web.url="*/check_telegram_updates.php" OR Web.url="*/mlog.php") BY Web.src | rename Web.src as dest] | eval delay_min=round((proc_time - visit_time)/60, 1) | where delay_min>=0 AND delay_min<=30 | convert ctime(proc_time) ctime(visit_time) | table proc_time, dest, user, process_name, parent, cmd, visit_time, visited_url, delay_min
```

**Defender KQL:**
```kql
let LookbackHours = 24h;
let CorrelationWindow = 30m;
let _rmm_bins = dynamic(["ScreenConnect.ClientSetup.exe","ScreenConnect.exe","ITarianClient.exe","ITSMAgent.exe","ConnectWiseControl.ClientSetup.exe","ConnectWiseControl.exe","LMI_Rescue.exe","Rescue.exe","LMI-Rescue-Calling-Card.exe","DattoRMMAgent.exe","AgentSetup_Default.exe","atrmm.exe","Aem.exe"]);
let _campaign_paths = dynamic(["/blocked.html","/Image/office360.png","/Image/office.png","/Image/yahoo.png","/Image/google.png","/Image/aol.png","/Image/email.png","/check_telegram_updates.php","/mlog.php","/pass.php"]);
let CampaignVisits = DeviceNetworkEvents
    | where Timestamp > ago(LookbackHours)
    | where isnotempty(RemoteUrl)
    | where RemoteUrl has_any (_campaign_paths)
    | project DeviceId, VisitTime = Timestamp, VisitedUrl = RemoteUrl;
DeviceProcessEvents
| where Timestamp > ago(LookbackHours)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","outlook.exe","explorer.exe","msiexec.exe")
| where FileName in~ (_rmm_bins)
| join kind=inner CampaignVisits on DeviceId
| where Timestamp between (VisitTime .. VisitTime + CorrelationWindow)
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          RmmBinary = FileName, ProcessCommandLine, FolderPath,
          VisitTime, VisitedUrl,
          DelayMin = datetime_diff('minute', Timestamp, VisitTime),
          SHA256
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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `festiveparty.us`, `getceptionparty.de`, `celebratieinvitiee.de`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
