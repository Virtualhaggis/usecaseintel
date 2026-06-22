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
- **T1656** — Impersonation
- **T1059.003** — Windows Command Shell
- **T1105** — Ingress Tool Transfer
- **T1074.001** — Local Data Staging
- **T1036.005** — Match Legitimate Name or Location
- **T1102.001** — Web Service: Dead Drop Resolver

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Fake Microsoft account security-alert spear-phish delivering ZIP-with-LNK (APT37/ScarCruft)

`UC_126_10` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Email.All_Email where All_Email.direction="inbound" (All_Email.subject="*security alert*" OR All_Email.subject="*one-time password*" OR All_Email.subject="*one time password*" OR All_Email.subject="*abnormal activity*" OR All_Email.subject="*unusual activity*" OR All_Email.subject="*OTP*") All_Email.file_name="*.zip" by All_Email.src_user, All_Email.recipient, All_Email.subject, All_Email.file_name, All_Email.message_id
| `drop_dm_object_name(All_Email)`
| where NOT match(src_user, "(?i)@(microsoft\.com|microsoftonline\.com|accountprotection\.microsoft\.com)$")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
EmailEvents
| where Timestamp > ago(LookbackDays)
| where EmailDirection == "Inbound"
| where DeliveryAction in ("Delivered","DeliveredAsSpam")
| where SenderDisplayName has_any ("Microsoft","Microsoft Account","Account Team","Account Security","Microsoft 계정")
   or Subject has_any ("account security","security alert","one-time password","OTP","unusual activity","abnormal activity","보안 알림","비정상","암호를 변경")
| where SenderFromDomain !endswith "microsoft.com" and SenderFromDomain !endswith "microsoftonline.com" and SenderFromDomain !endswith "accountprotection.microsoft.com"
| join kind=inner (
    EmailAttachmentInfo
    | where Timestamp > ago(LookbackDays)
    | where FileName endswith ".zip"
  ) on NetworkMessageId
| project Timestamp, NetworkMessageId, SenderFromAddress, SenderDisplayName, SenderFromDomain, RecipientEmailAddress, Subject, FileName, FileType, SHA256, DeliveryAction, AuthenticationDetails
| order by Timestamp desc
```

### NarwhalRAT LNK-spawned batch downloader fetching payload + CAT file from APT37 C2

`UC_126_11` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","curl.exe","certutil.exe","bitsadmin.exe","mshta.exe")) (Processes.process="*daehoat.com*" OR Processes.process="*novel21.co.kr*" OR Processes.process="*fe01.co.kr*" OR Processes.process="*webhostingkorea.com*" OR Processes.process="*crwellfood.com*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let LookbackDays = 14d;
let C2Domains = dynamic(["daehoat.com","novel21.co.kr","fe01.co.kr","webhostingkorea.com","crwellfood.com"]);
DeviceProcessEvents
| where Timestamp > ago(LookbackDays)
| where AccountName !endswith "$"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","curl.exe","certutil.exe","bitsadmin.exe","mshta.exe")
| where ProcessCommandLine has_any (C2Domains)
   or (ProcessCommandLine has ".cat" and ProcessCommandLine has_any ("http://","https://","DownloadFile","DownloadString","-urlcache","Start-BitsTransfer","Invoke-WebRequest"))
| where InitiatingProcessFileName in~ ("explorer.exe","cmd.exe","wscript.exe","cscript.exe","powershell.exe")
| project Timestamp, DeviceName, AccountName, ParentProcess = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### NarwhalRAT scheduled-task persistence by exact task name (MicrosoftUserInterfacePicturesUpdateTackMachine)

`UC_126_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="schtasks.exe" (Processes.process="*MicrosoftUserInterfacePicturesUpdateTackMachine*" OR Processes.process="*MicrosoftMusicLibrariesPackageTaskMachine*") by Processes.dest Processes.user Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("MicrosoftUserInterfacePicturesUpdateTackMachine","MicrosoftMusicLibrariesPackageTaskMachine")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### NarwhalRAT 'naverwhale' staging directory under %APPDATA%

`UC_126_13` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\AppData\\Roaming\\naverwhale*" OR Filesystem.file_path="*\\naverwhale\\*") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\AppData\Roaming\naverwhale" or FolderPath has @"\naverwhale\"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### NarwhalRAT C2 to APT37 Korean relay domains/IPs

`UC_126_14` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("121.254.222.10","121.254.222.80","211.239.157.126","218.150.78.198","218.150.78.231","61.100.9.206")) OR (All_Traffic.dest_host IN ("daehoat.com","novel21.co.kr","fe01.co.kr","webhostingkorea.com","crwellfood.com")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let C2Domains = dynamic(["daehoat.com","novel21.co.kr","fe01.co.kr","webhostingkorea.com","crwellfood.com"]);
let C2IPs = dynamic(["121.254.222.10","121.254.222.80","211.239.157.126","218.150.78.198","218.150.78.231","61.100.9.206"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (C2Domains) or RemoteIP in (C2IPs)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType
| order by Timestamp desc
```

### NarwhalRAT pCloud dead-drop resolver secondary C2 from Python loader

`UC_126_15` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_host="*pcloud.com*" (All_Traffic.app="python.exe" OR All_Traffic.app="pythonw.exe" OR All_Traffic.process_name="python.exe" OR All_Traffic.process_name="pythonw.exe") by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let NaverwhaleHosts = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FolderPath has "naverwhale"
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "pcloud.com"
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName in~ ("python.exe","pythonw.exe") or InitiatingProcessFolderPath has @"\AppData\" or DeviceId in (NaverwhaleHosts)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
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

Severity classified as **CRIT** based on: IOCs present, 16 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
