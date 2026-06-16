# [CRIT] Fake Microsoft Alerts Used to Deploy North Korean NarwhalRAT Malware

**Source:** The Hacker News
**Published:** 2026-06-16
**Article:** https://thehackernews.com/2026/06/fake-microsoft-alerts-used-to-deploy.html

## Threat Profile

Fake Microsoft Alerts Used to Deploy North Korean NarwhalRAT Malware 
 Ravie Lakshmanan  Jun 16, 2026 Malware / Cyber Attack 
The North Korean state-sponsored hacking group known as ScarCruft (aka APT37) has been observed using spear-phishing messages impersonating Microsoft Account security notifications to deliver malware called NarwhalRAT .
"The attack email contained a message impersonating an MS account security alert," the Genians Security Center (GSC) said . "It was designed to create c…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `121.254.222.10`
- **IPv4 (defanged):** `121.254.222.80`
- **IPv4 (defanged):** `211.239.157.126`
- **IPv4 (defanged):** `218.150.78.198`
- **IPv4 (defanged):** `218.150.78.231`
- **IPv4 (defanged):** `61.100.9.206`
- **Domain (defanged):** `daehoat.com`
- **Domain (defanged):** `novel21.co.kr`
- **Domain (defanged):** `fe01.co.kr`
- **Domain (defanged):** `webhostingkorea.com`
- **Domain (defanged):** `crwellfood.com`
- **MD5:** `3715092aa00f380cefe8b4d2eddb7d08`
- **MD5:** `7cef19f9c4480adac0cd4702ff98f46c`
- **MD5:** `7eb9cee1f696727752169f25cf79a338`
- **MD5:** `b6b0602310bb2d4360c52685119aac1b`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1036.005** — Match Legitimate Name or Location
- **T1074.001** — Local Data Staging
- **T1036.004** — Masquerade Task or Service
- **T1056.001** — Keylogging
- **T1102.002** — Web Service: Bidirectional Communication
- **T1567.002** — Exfiltration to Cloud Storage
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1090** — Proxy
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1036.008** — Masquerade File Type
- **T1620** — Reflective Code Loading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Fake Microsoft OTP/security-alert phish with ZIP+LNK attachment (APT37)

`UC_10_10` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email where Email.file_name="*.lnk" Email.message_direction="inbound" by Email.src_user Email.recipient Email.subject Email.file_name Email.file_hash Email.message_id | `drop_dm_object_name(Email)` | search subject IN ("*Microsoft*account*","*OTP*","*one-time*password*","*security alert*","*abnormal activity*","*account compromise*") AND file_name="*.lnk"
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let LureTerms = dynamic(["microsoft account","one-time password","otp","abnormal activity","account compromise","security alert","unusual sign-in","password change"]);
let ScarCruftMail = EmailEvents
    | where Timestamp > ago(LookbackDays)
    | where EmailDirection == "Inbound" and DeliveryAction in ("Delivered","DeliveredAsSpam")
    | where Subject has_any (LureTerms);
ScarCruftMail
| join kind=inner (
    EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where FileType =~ "zip" or FileName endswith ".zip"
    | project NetworkMessageId, ZipName = FileName, ZipSHA256 = SHA256, ZipSize = FileSize
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderMailFromDomain,
          RecipientEmailAddress, Subject, ZipName, ZipSHA256, ZipSize, DeliveryAction
| order by Timestamp desc
```

### NarwhalRAT scheduled task persistence with Microsoft*Task naming

`UC_10_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("schtasks.exe","powershell.exe","cmd.exe") Processes.process="*Microsoft*Task*Machine*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | regex process="(?i)Microsoft(UserInterfacePictures|MusicLibrariesPackage|[A-Z][A-Za-z]+)(Update|Package)?Ta(s|c)kMachine"
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where FileName =~ "schtasks.exe" or InitiatingProcessFileName =~ "schtasks.exe"
   or ProcessCommandLine has_any ("schtasks /create","Register-ScheduledTask","New-ScheduledTask")
| where ProcessCommandLine matches regex @"(?i)Microsoft[A-Z][A-Za-z]{3,}(Update|Package)?Ta[sc]kMachine"
   or ProcessCommandLine has_any ("MicrosoftUserInterfacePicturesUpdateTackMachine","MicrosoftMusicLibrariesPackageTaskMachine")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### NarwhalRAT %APPDATA%\naverwhale staging directory creation

`UC_10_12` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\AppData\\Roaming\\naverwhale\\*" by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
DeviceFileEvents
| where Timestamp > ago(LookbackDays)
| where FolderPath has @"\AppData\Roaming\naverwhale"
   or FolderPath has @"\AppData\Local\naverwhale"
| where InitiatingProcessFileName !in~ ("whale.exe","whale_update.exe","NaverWhaleInstaller.exe")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName
| order by Timestamp desc
```

### Python process abusing pCloud API with folderid + auth dead-drop parameters

`UC_10_13` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*api*pcloud*" Web.url="*folderid=*" Web.url="*auth=*" by Web.src Web.user Web.url Web.http_user_agent Web.process | `drop_dm_object_name(Web)` | where like(process,"%python%") OR like(http_user_agent,"%python%") OR like(http_user_agent,"%requests%")
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let PCloudHosts = dynamic(["api.pcloud.com","eapi.pcloud.com","papi.pcloud.com","binapi.pcloud.com"]);
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where RemoteUrl has_any (PCloudHosts) or RemoteUrl has "pcloud.com"
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe","py.exe")
   or InitiatingProcessCommandLine has_any ("folderid=","auth=")
   or InitiatingProcessFolderPath has @"\AppData\"
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where FileName in~ ("python.exe","pythonw.exe")
    | project DeviceId, PyPid = ProcessId, PyCmd = ProcessCommandLine, PyParent = InitiatingProcessFileName
  ) on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          RemoteUrl, RemoteIP, RemotePort, PyCmd, PyParent
| order by Timestamp desc
```

### Outbound connection to NarwhalRAT C2 IP set (Korean-hosted infrastructure)

`UC_10_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (Network_Traffic.dest_ip IN ("121.254.222.10","121.254.222.80","211.239.157.126","218.150.78.198","218.150.78.231","61.100.9.206") OR Network_Traffic.dest="daehoat.com" OR Network_Traffic.dest="*daehoat.com" OR Network_Traffic.dest="novel21.co.kr" OR Network_Traffic.dest="*novel21.co.kr" OR Network_Traffic.dest="fe01.co.kr" OR Network_Traffic.dest="*fe01.co.kr" OR Network_Traffic.dest="webhostingkorea.com" OR Network_Traffic.dest="crwellfood.com") by Network_Traffic.src Network_Traffic.dest Network_Traffic.dest_ip Network_Traffic.dest_port Network_Traffic.app | `drop_dm_object_name(Network_Traffic)`
```

**Defender KQL:**
```kql
let LookbackDays = 30d;
let NarwhalIPs = dynamic(["121.254.222.10","121.254.222.80","211.239.157.126","218.150.78.198","218.150.78.231","61.100.9.206"]);
let NarwhalDomains = dynamic(["daehoat.com","novel21.co.kr","fe01.co.kr","webhostingkorea.com","crwellfood.com"]);
union
(
    DeviceNetworkEvents
    | where Timestamp > ago(LookbackDays)
    | where RemoteIP in (NarwhalIPs)
       or RemoteUrl has_any (NarwhalDomains)
    | project Timestamp, DeviceName, ActionType,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, InitiatingProcessSHA256,
              RemoteIP, RemotePort, RemoteUrl
),
(
    DeviceEvents
    | where Timestamp > ago(LookbackDays)
    | where ActionType == "DnsQueryResponse"
    | where RemoteUrl has_any (NarwhalDomains)
    | project Timestamp, DeviceName, ActionType,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessFolderPath, InitiatingProcessSHA256,
              RemoteIP = tostring(parse_json(AdditionalFields).IPAddress),
              RemotePort = int(null), RemoteUrl
)
| order by Timestamp desc
```

### NarwhalRAT loader hash detection across endpoint telemetry

`UC_10_15` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint where (Endpoint.Processes.process_hash IN ("3715092aa00f380cefe8b4d2eddb7d08","7cef19f9c4480adac0cd4702ff98f46c","7eb9cee1f696727752169f25cf79a338","b6b0602310bb2d4360c52685119aac1b") OR Endpoint.Filesystem.file_hash IN ("3715092aa00f380cefe8b4d2eddb7d08","7cef19f9c4480adac0cd4702ff98f46c","7eb9cee1f696727752169f25cf79a338","b6b0602310bb2d4360c52685119aac1b")) by Endpoint.dest Endpoint.user
```

**Defender KQL:**
```kql
let NarwhalHashes = dynamic(["3715092aa00f380cefe8b4d2eddb7d08","7cef19f9c4480adac0cd4702ff98f46c","7eb9cee1f696727752169f25cf79a338","b6b0602310bb2d4360c52685119aac1b"]);
union
(
    DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where MD5 in (NarwhalHashes) or InitiatingProcessMD5 in (NarwhalHashes)
    | project Timestamp, DeviceName, AccountName, Source = "Process",
              FileName, FolderPath, MD5, SHA256, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine
),
(
    DeviceFileEvents
    | where Timestamp > ago(90d)
    | where MD5 in (NarwhalHashes)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Source = "File",
              FileName, FolderPath, MD5, SHA256, ProcessCommandLine = InitiatingProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine
),
(
    DeviceImageLoadEvents
    | where Timestamp > ago(90d)
    | where MD5 in (NarwhalHashes)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, Source = "ImageLoad",
              FileName, FolderPath, MD5, SHA256, ProcessCommandLine = InitiatingProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine
)
| order by Timestamp desc
```

### Compiled Python payload loaded from CAT-file scheduled task

`UC_10_16` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="taskeng.exe" OR Processes.parent_process_name="svchost.exe" Processes.process_name IN ("python.exe","pythonw.exe") (Processes.process="*.cat*" OR Processes.process="*\\AppData\\*\\python.exe*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT match(process,"(?i)\\\\Program Files\\\\(Python|Anaconda)")
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where FileName in~ ("python.exe","pythonw.exe")
| where ProcessCommandLine has ".cat"
   or ProcessCommandLine matches regex @"(?i)\\AppData\\(Roaming|Local)\\[^\\]+\\python\.exe"
   or InitiatingProcessFileName in~ ("taskeng.exe","svchost.exe")
      and InitiatingProcessCommandLine has_any ("MicrosoftUserInterfacePictures","MicrosoftMusicLibraries","TaskMachine","TackMachine")
| where InitiatingProcessParentFileName !in~ ("explorer.exe","code.exe","pycharm64.exe","jupyter.exe")
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine, ChildFolder = FolderPath, SHA256
| order by Timestamp desc
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

### Scheduled task created with suspicious image / encoded args

`UC_SCHEDULED_TASK` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
      AND (Processes.process="*powershell*" OR Processes.process="*cmd.exe*"
        OR Processes.process="*rundll32*" OR Processes.process="*-enc*"
        OR Processes.process="*FromBase64*" OR Processes.process="*\Users\Public*"
        OR Processes.process="*\AppData\*")
    by Processes.dest, Processes.user, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell","cmd.exe","rundll32","-enc","FromBase64","\Users\Public","\AppData\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
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

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `121.254.222.10`, `121.254.222.80`, `211.239.157.126`, `218.150.78.198`, `218.150.78.231`, `61.100.9.206`, `daehoat.com`, `novel21.co.kr` _(+3 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `3715092aa00f380cefe8b4d2eddb7d08`, `7cef19f9c4480adac0cd4702ff98f46c`, `7eb9cee1f696727752169f25cf79a338`, `b6b0602310bb2d4360c52685119aac1b`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 17 use case(s) fired, 27 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
