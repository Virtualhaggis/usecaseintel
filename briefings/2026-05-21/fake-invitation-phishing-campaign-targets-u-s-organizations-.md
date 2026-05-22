# [CRIT] Fake Invitation Phishing Campaign Targets U.S. Organizations With Credential Theft

**Source:** Cyber Security News
**Published:** 2026-05-21
**Article:** https://cybersecuritynews.com/fake-invitation-phishing-campaign/

## Threat Profile

Home Cyber Security News 
Fake Invitation Phishing Campaign Targets U.S. Organizations With Credential Theft 
By Tushar Subhra Dutta 
May 21, 2026 
A large-scale phishing campaign is actively targeting U.S. organizations, using fake event invitations as bait to steal login credentials, intercept one-time passwords, or install remote access tools. 
The operation has been running since at least December 2025, with researchers tracking a growing pool of malicious domains built around the same repea…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `festiveparty.us`
- **Domain (defanged):** `getceptionparty.de`
- **Domain (defanged):** `celebratieinvitiee.de`
- **SHA256:** `887bc414bdb32b83dcfccdd3c688e90d9a87a0033e3756a840f9bdd2d65c5c74`
- **SHA256:** `6eaa0a448f1306bcf4159783eeafe5d37243bd8ca2728db7d90de1929241dd29`
- **SHA256:** `4c373bc25cb71dbb75e73b61dff25aa184be8d327053a97202a6b1a5919cab0d`
- **SHA256:** `a838f99537d35e48e479a34086297f76db5d3363b0456f23d10d308f0d30ed82`
- **SHA256:** `8e94c18bbcad0644c4b04de4356fe37da9996fdf1c99bc984ba819862a9b1889`
- **SHA256:** `9a53e032a6e3e79861d28568c3b6ffc97f4f3c1d3af65a703ec12966420503d9`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1566.002** — Phishing: Spearphishing Link
- **T1056.003** — Input Capture: Web Portal Capture
- **T1041** — Exfiltration Over C2 Channel
- **T1583.001** — Acquire Infrastructure: Domains
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Phishing credential exfil POST to /processmail.php /process.php /pass.php /mlog.php endpoints

`UC_12_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user) as user values(Web.dest) as dest from datamodel=Web.Web where Web.http_method=POST AND (Web.url="*/processmail.php*" OR Web.url="*/process.php*" OR Web.url="*/pass.php*" OR Web.url="*/mlog.php*" OR Web.url="*/check_telegram_updates.php*") by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | where NOT match(dest,"(?i)\.(microsoft|office|google|yahoo|aol)\.com$")
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where RemoteUrl has_any ("/processmail.php","/process.php","/pass.php","/mlog.php","/check_telegram_updates.php")
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Fake-invitation phishing site fingerprint: sequential GET /blocked.html /favicon.ico /Image/*.png

`UC_12_11` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls from datamodel=Web.Web where (Web.url="*/blocked.html*" OR Web.url="*/Image/office360.png" OR Web.url="*/Image/office.png" OR Web.url="*/Image/yahoo.png" OR Web.url="*/Image/google.png" OR Web.url="*/Image/aol.png" OR Web.url="*/Image/email.png") by Web.src Web.dest _time span=5m | `drop_dm_object_name(Web)` | eval hit_blocked=if(match(urls,"/blocked\.html"),1,0), hit_image=if(match(urls,"/Image/(office360|office|yahoo|google|aol|email)\.png"),1,0) | where hit_blocked=1 AND hit_image=1
```

**Defender KQL:**
```kql
let kitIcons = dynamic(["/Image/office360.png","/Image/office.png","/Image/yahoo.png","/Image/google.png","/Image/aol.png","/Image/email.png"]);
let kitHashes = dynamic(["887bc414bdb32b83dcfccdd3c688e90d9a87a0033e3756a840f9bdd2d65c5c74","6eaa0a448f1306bcf4159783eeafe5d37243bd8ca2728db7d90de1929241dd29","4c373bc25cb71dbb75e73b61dff25aa184be8d327053a97202a6b1a5919cab0d","a838f99537d35e48e479a34086297f76db5d3363b0456f23d10d308f0d30ed82","8e94c18bbcad0644c4b04de4356fe37da9996fdf1c99bc984ba819862a9b1889","9a53e032a6e3e79861d28568c3b6ffc97f4f3c1d3af65a703ec12966420503d9"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where RemoteUrl has_any (kitIcons) or RemoteUrl has "/blocked.html"
| extend HitBlocked = iff(RemoteUrl has "/blocked.html",1,0), HitIcon = iff(RemoteUrl has_any (kitIcons),1,0), HostDomain = parse_url(RemoteUrl).Host
| summarize BlockedHits=sum(HitBlocked), IconHits=sum(HitIcon), Urls=make_set(RemoteUrl,20), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessAccountUpn, HostDomain, bin(Timestamp, 5m)
| where BlockedHits >= 1 and IconHits >= 1
| union (
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where SHA256 in (kitHashes)
    | project DeviceName, InitiatingProcessAccountUpn, HostDomain=FileOriginUrl, Urls=pack_array(FileName), BlockedHits=0, IconHits=1, FirstSeen=Timestamp, LastSeen=Timestamp, Timestamp
)
| order by LastSeen desc
```

### [LLM] Outbound traffic to known fake-invitation phishing domains (festiveparty.us, getceptionparty.de, celebratieinvitiee.de)

`UC_12_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls values(Web.user) as user from datamodel=Web.Web where Web.dest IN ("festiveparty.us","getceptionparty.de","celebratieinvitiee.de") OR Web.url IN ("*festiveparty.us*","*getceptionparty.de*","*celebratieinvitiee.de*") by Web.src Web.dest | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
let phishDomains = dynamic(["festiveparty.us","getceptionparty.de","celebratieinvitiee.de"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (phishDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, RemoteUrl, RemoteIP, ActionType
| union (
    UrlClickEvents
    | where Timestamp > ago(30d)
    | where Url has_any (phishDomains)
    | project Timestamp, DeviceName="(email-click)", InitiatingProcessAccountUpn=AccountUpn, InitiatingProcessFileName="(email)", RemoteUrl=Url, RemoteIP=IPAddress, ActionType
)
| order by Timestamp desc
```

### [LLM] Drive-by RMM tool installer download (ScreenConnect, ITarian, Datto, ConnectWise, LogMeIn Rescue) following browser session

`UC_12_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe") AND (Filesystem.file_name="*ScreenConnect*" OR Filesystem.file_name="*ConnectWiseControl*" OR Filesystem.file_name="*ITarian*" OR Filesystem.file_name="*ITSMService*" OR Filesystem.file_name="*DattoRMM*" OR Filesystem.file_name="*AEMAgent*" OR Filesystem.file_name="*LMI_Rescue*" OR Filesystem.file_name="*LogMeIn*Rescue*") by Filesystem.dest Filesystem.user Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe")
| where ActionType == "FileCreated"
| where (FileName has_any ("ScreenConnect","ConnectWiseControl","ConnectWise.ClientSetup","ITarian","ITSMService","DattoRMM","AEMAgent","LMI_Rescue","LogMeInRescue"))
  and (FileName endswith ".exe" or FileName endswith ".msi" or FileName endswith ".client.exe")
| extend SourceDomain = tostring(parse_url(FileOriginUrl).Host)
| where SourceDomain !endswith "screenconnect.com" and SourceDomain !endswith "connectwise.com" and SourceDomain !endswith "itarian.com" and SourceDomain !endswith "comodo.com" and SourceDomain !endswith "datto.com" and SourceDomain !endswith "centrastage.net" and SourceDomain !endswith "logmeinrescue.com" and SourceDomain !endswith "logmein.com" and SourceDomain !endswith "goto.com"
| project Timestamp, DeviceName, InitiatingProcessAccountUpn, InitiatingProcessFileName, FileName, FolderPath, SHA256, FileOriginUrl, SourceDomain
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `festiveparty.us`, `getceptionparty.de`, `celebratieinvitiee.de`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `887bc414bdb32b83dcfccdd3c688e90d9a87a0033e3756a840f9bdd2d65c5c74`, `6eaa0a448f1306bcf4159783eeafe5d37243bd8ca2728db7d90de1929241dd29`, `4c373bc25cb71dbb75e73b61dff25aa184be8d327053a97202a6b1a5919cab0d`, `a838f99537d35e48e479a34086297f76db5d3363b0456f23d10d308f0d30ed82`, `8e94c18bbcad0644c4b04de4356fe37da9996fdf1c99bc984ba819862a9b1889`, `9a53e032a6e3e79861d28568c3b6ffc97f4f3c1d3af65a703ec12966420503d9`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
