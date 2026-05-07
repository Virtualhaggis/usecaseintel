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
Once clicked, those links lead to pages designed to s…

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
- **T1056.003** — Input Capture: Web Portal Capture
- **T1111** — Multi-Factor Authentication Interception
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Event-Invitation Phishing Page Fingerprint: /blocked.html + /favicon.ico + /Image/<brand>.png Chain

`UC_0_9` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true values(Web.url) as urls count from datamodel=Web where (Web.url="*/blocked.html" OR Web.url="*/favicon.ico" OR Web.url="*/Image/office360.png" OR Web.url="*/Image/office.png" OR Web.url="*/Image/yahoo.png" OR Web.url="*/Image/google.png" OR Web.url="*/Image/aol.png" OR Web.url="*/Image/email.png") by Web.src, Web.dest, _time span=10m | `drop_dm_object_name(Web)` | eval url_str=mvjoin(urls, "|") | eval has_blocked=if(match(url_str, "/blocked\.html"),1,0) | eval has_favicon=if(match(url_str, "/favicon\.ico"),1,0) | eval has_brand=if(match(url_str, "/Image/(office360|office|yahoo|google|aol|email)\.png"),1,0) | where has_blocked=1 AND has_favicon=1 AND has_brand=1 | table _time, src, dest, urls
```

**Defender KQL:**
```kql
// Event-invitation phish-kit URL fingerprint — three-leg request chain on same dest in 10m window
let LookbackDays = 7d;
let WindowMinutes = 10m;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where isnotempty(RemoteUrl)
// Pre-filter to the kit's known paths (cheap term-aligned matches)
| where RemoteUrl has_any ("/blocked.html","/favicon.ico","/Image/office360.png","/Image/office.png","/Image/yahoo.png","/Image/google.png","/Image/aol.png","/Image/email.png")
| extend Host = tostring(parse_url(RemoteUrl).Host)
| where isnotempty(Host)
// Bucket per device + destination host in 10-minute windows
| summarize Urls = make_set(RemoteUrl, 50),
            Hits = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp)
            by DeviceId, DeviceName, Host, bin(Timestamp, WindowMinutes)
| extend UrlBlob = strcat_array(Urls, "|")
| where UrlBlob has "/blocked.html"
     and UrlBlob has "/favicon.ico"
     and UrlBlob matches regex @"/Image/(office360|office|yahoo|google|aol|email)\.png"
| project FirstSeen, LastSeen, DeviceName, Host, Hits, Urls
| order by FirstSeen desc
```

### [LLM] RMM Installer (ScreenConnect/ConnectWise/LogMeIn Rescue/Datto/ITarian) Dropped From Browser Visit to Event-Themed Lure

`UC_0_10` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Endpoint.Filesystem.file_path) as path, values(Endpoint.Filesystem.process_name) as proc, values(Endpoint.Filesystem.file_origin_url) as origin from datamodel=Endpoint.Filesystem where (Endpoint.Filesystem.file_name="ScreenConnect.ClientSetup.exe" OR Endpoint.Filesystem.file_name="ScreenConnect.ClientService.exe" OR Endpoint.Filesystem.file_name="ConnectWiseControl.ClientSetup.exe" OR Endpoint.Filesystem.file_name="ConnectWiseControl.exe" OR Endpoint.Filesystem.file_name="LMI_Rescue.exe" OR Endpoint.Filesystem.file_name="LMI-Rescue*.exe" OR Endpoint.Filesystem.file_name="DattoRMM*.exe" OR Endpoint.Filesystem.file_name="AEM*.exe" OR Endpoint.Filesystem.file_name="ITarian*.exe" OR Endpoint.Filesystem.file_name="Comodo*RMM*.exe") (Endpoint.Filesystem.process_name="chrome.exe" OR Endpoint.Filesystem.process_name="msedge.exe" OR Endpoint.Filesystem.process_name="firefox.exe" OR Endpoint.Filesystem.process_name="brave.exe" OR Endpoint.Filesystem.process_name="outlook.exe") by Endpoint.Filesystem.dest, Endpoint.Filesystem.user, Endpoint.Filesystem.file_name, _time | `drop_dm_object_name(Endpoint.Filesystem)` | search origin IN ("*festiveparty*","*getceptionparty*","*celebratieinvitiee*","*party*","*event*","*invit*","*celebrat*","*festive*","*.de/*")
```

**Defender KQL:**
```kql
// RMM installer dropped by browser with origin URL on event-themed/.de phishing host
let LookbackDays = 7d;
let RmmFiles = dynamic(["ScreenConnect.ClientSetup","ScreenConnect.ClientService","ConnectWiseControl","LMI_Rescue","LMI-Rescue","DattoRMM","AEMAgent","ITarian","Comodo"]);
let KnownPhishHosts = dynamic(["festiveparty.us","getceptionparty.de","celebratieinvitiee.de"]);
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","outlook.exe")
| where FileName has_any (RmmFiles)
     or FileName matches regex @"(?i)^(screenconnect|connectwise|logmein|lmi[-_]?rescue|datto|itarian|comodo).*\.(exe|msi)$"
| where isnotempty(FileOriginUrl)
| extend OriginHost = tolower(tostring(parse_url(FileOriginUrl).Host))
| where OriginHost in (KnownPhishHosts)
     or OriginHost endswith ".de"
     or OriginHost has_any ("party","event","invit","celebrat","festive","gathering")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, FileName, FolderPath,
          FileOriginUrl, FileOriginReferrerUrl, OriginHost, SHA256
| order by Timestamp desc
```

### [LLM] Endpoint Beacon to Event-Phish Credential/OTP Exfil PHP Endpoints (/pass.php /mlog.php /processmail.php /process.php /check_telegram_updates

`UC_0_11` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Web.url) as urls, values(Web.http_method) as methods from datamodel=Web where (Web.url="*/pass.php" OR Web.url="*/mlog.php" OR Web.url="*/processmail.php" OR Web.url="*/process.php" OR Web.url="*/check_telegram_updates.php") by Web.src, Web.user, Web.dest, _time span=5m | `drop_dm_object_name(Web)` | eval endpoint_type=case(match(mvjoin(urls,"|"),"/pass\.php|/mlog\.php"),"google_creds", match(mvjoin(urls,"|"),"/processmail\.php"),"non_google_creds", match(mvjoin(urls,"|"),"/process\.php"),"otp_submit", match(mvjoin(urls,"|"),"/check_telegram_updates\.php"),"visitor_beacon") | table _time, src, user, dest, endpoint_type, urls, methods
```

**Defender KQL:**
```kql
// Hits to the event-phish kit's credential/OTP exfil PHP endpoints
let LookbackDays = 7d;
let ExfilPaths = dynamic(["/pass.php","/mlog.php","/processmail.php","/process.php","/check_telegram_updates.php"]);
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any (ExfilPaths)
| extend Host = tostring(parse_url(RemoteUrl).Host)
| extend EndpointType = case(
    RemoteUrl has "/pass.php" or RemoteUrl has "/mlog.php", "GoogleCredential",
    RemoteUrl has "/processmail.php", "NonGoogleCredential",
    RemoteUrl has "/process.php", "OTPSubmission",
    RemoteUrl has "/check_telegram_updates.php", "VisitorBeacon",
    "Unknown")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, EndpointType,
          RemoteUrl, Host, RemoteIP, RemotePort
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
