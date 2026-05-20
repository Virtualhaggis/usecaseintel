# [CRIT] Hackers Abuse MSHTA Legacy Windows Tool to Deliver LummaStealer and Amatera Malware

**Source:** Cyber Security News
**Published:** 2026-05-20
**Article:** https://cybersecuritynews.com/hackers-abuse-mshta-legacy-windows-tool/

## Threat Profile

Home Cyber Security News 
Hackers Abuse MSHTA Legacy Windows Tool to Deliver LummaStealer and Amatera Malware 
By Tushar Subhra Dutta 
May 20, 2026 
Hackers are exploiting a decades-old Windows tool to deliver dangerous malware onto unsuspecting systems, with consequences ranging from stolen passwords to full system compromise. 
The tool is MSHTA, short for Microsoft HTML Application Host, a built-in Windows utility that can run scripts from local files and remote internet locations. 
Attackers …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `185.147.124.40`
- **IPv4 (defanged):** `92.255.57.155`
- **IPv4 (defanged):** `185.208.159.199`
- **IPv4 (defanged):** `87.96.21.84`
- **IPv4 (defanged):** `58.221.252.210`
- **IPv4 (defanged):** `60.173.116.152`
- **IPv4 (defanged):** `61.136.101.152`
- **IPv4 (defanged):** `61.147.108.92`
- **IPv4 (defanged):** `89.117.2.159`
- **IPv4 (defanged):** `100.1.121.27`
- **IPv4 (defanged):** `103.36.223.87`
- **IPv4 (defanged):** `103.55.70.212`
- **IPv4 (defanged):** `103.83.212.194`
- **IPv4 (defanged):** `103.115.17.90`
- **IPv4 (defanged):** `103.113.195.244`
- **IPv4 (defanged):** `107.175.187.11`
- **IPv4 (defanged):** `110.42.51.229`
- **IPv4 (defanged):** `110.45.196.155`
- **IPv4 (defanged):** `122.165.219.142`
- **IPv4 (defanged):** `156.224.232.98`
- **IPv4 (defanged):** `157.66.153.154`
- **IPv4 (defanged):** `173.208.166.226`
- **IPv4 (defanged):** `187.102.48.229`
- **IPv4 (defanged):** `190.111.12.242`
- **IPv4 (defanged):** `193.112.70.226`
- **IPv4 (defanged):** `201.138.238.195`
- **IPv4 (defanged):** `204.44.110.216`
- **IPv4 (defanged):** `222.73.29.92`
- **Domain (defanged):** `memory-scanner.cc`
- **Domain (defanged):** `fileless-market.cc`
- **Domain (defanged):** `google-services.cc`
- **Domain (defanged):** `system-monitor.cc`
- **Domain (defanged):** `files-storage.cc`
- **Domain (defanged):** `web3-walletnotify.cc`
- **Domain (defanged):** `debank-api.cc`
- **Domain (defanged):** `py-installer.cc`
- **Domain (defanged):** `sentinel1-endpoint-security.cc`
- **Domain (defanged):** `explorer.vg`
- **Domain (defanged):** `ccleaner.gl`
- **Domain (defanged):** `microservice.gl`
- **Domain (defanged):** `geo-foundation.vg`
- **Domain (defanged):** `deluxe.gl`
- **Domain (defanged):** `silverhost.vg`
- **Domain (defanged):** `msgrouppolicy.vg`
- **Domain (defanged):** `holypriest.gl`
- **Domain (defanged):** `msedge.vg`
- **Domain (defanged):** `ms-team-ping6.com`
- **Domain (defanged):** `holiday-updateservice.com`
- **Domain (defanged):** `health-smooth-eu2.com`
- **Domain (defanged):** `health-smooth-eu3.com`
- **Domain (defanged):** `bigbrainsholdings.com`
- **Domain (defanged):** `my-smart-house1.com`
- **Domain (defanged):** `d6shiiwz.pw`
- **Domain (defanged):** `s7610rir.pw`
- **Domain (defanged):** `pool4883.pw`
- **Domain (defanged):** `somepools555.pw`
- **Domain (defanged):** `macphotoeditor.shop`
- **Domain (defanged):** `antibot-check.icu`
- **SHA256:** `AA845A8FB4AB38AEBE6A16A2A8F80CA4467AC0991D3EEF4D8A10BDF97DEDB1E9`
- **SHA256:** `02630FA994B1566AD1515FD87220FC037B967F07495985A3637D68D7E08C57EE`
- **SHA256:** `1E0E375F3EE82D5AF5DFE6F7DF0E2FAC9A7D37C67ADD3390D05A93AFD85B7C84`
- **SHA256:** `333E2192F2551415659FB4094E81B911708921BB588EECF65E27F51C9938DFC2`
- **SHA256:** `38FE562136ADE372FC4CEDDE67826AEEA8404E93A54A4A4736DDB4C8C8D4C96D`
- **SHA256:** `7D0487AFC91B0FE8B2FBF732AB54C3C07E86BF69471BBA6C283AABEA190499BA`

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1219** — Remote Access Software
- **T1543.001** — Persistence (article-specific)
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1036.003** — Masquerading: Rename System Utilities
- **T1566.002** — Phishing: Spearphishing Link
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Renamed MSHTA (iso2022.exe) spawned by Python Setup.exe loader

`UC_19_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.process_hash) as hash from datamodel=Endpoint.Processes where Processes.original_file_name="mshta.exe" Processes.process_name!="mshta.exe" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where parent_process_name IN ("python.exe","pythonw.exe","Setup.exe") OR match(process_name,"(?i)iso2022\.exe$") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessVersionInfoOriginalFileName =~ "mshta.exe" or ProcessVersionInfoInternalFileName =~ "mshta.exe"
| where FileName !~ "mshta.exe"
| where AccountName !endswith "$"
| extend RenamedAs = FileName, OriginalBinary = ProcessVersionInfoOriginalFileName
| project Timestamp, DeviceName, AccountName, RenamedAs, OriginalBinary, FolderPath, ProcessCommandLine,
          ParentName = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] MSHTA spawned by explorer.exe via Win+R ClickFix paste

`UC_19_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.parent_process_name="explorer.exe" Processes.process_name="mshta.exe" by Processes.dest Processes.user Processes.process | `drop_dm_object_name(Processes)` | where match(process,"(?i)https?://") OR match(process,"(?i)\.(mp4|mp3|eml|json|html|hta)(\b|$)") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName =~ "mshta.exe"
| where ProcessCommandLine matches regex @"(?i)https?://"
   or ProcessCommandLine matches regex @"(?i)\.(mp4|mp3|eml|json|html|hta)(\s|\"|$)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] MSHTA fetching Capcha.html / recaptcha-verify ClickFix landing page

`UC_19_13` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="mshta.exe" OR Processes.original_file_name="mshta.exe") by Processes.dest Processes.user Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | where match(process,"(?i)(Capcha\.html|recaptcha-verify\.html|singl[56]\.mp4|re[25]\.mp4|s[567]\.(mp3|mp4)|RIWZ\.mp4|madonna\.mp4|web44\.mp4|anrek\.mp4|mine\.json|ru2-2\.eml|awjxs\.captcha|awjsx\.captcha)") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "mshta.exe" or ProcessVersionInfoOriginalFileName =~ "mshta.exe"
| where ProcessCommandLine matches regex @"(?i)(Capcha\.html|recaptcha-verify\.html|singl[56]\.mp4|re[25]\.mp4|s[567]\.(mp3|mp4)|RIWZ\.mp4|madonna\.mp4|web44\.mp4|anrek\.mp4|mine\.json|ru2-2\.eml|awjxs\.captcha|awjsx\.captcha|S6\.mp4)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] MSHTA C2 retrieval to CountLoader / Emmenhtal infrastructure

`UC_19_14` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.process_name="mshta.exe" OR All_Traffic.process_name="iso2022.exe") (All_Traffic.dest IN ("memory-scanner.cc","fileless-market.cc","google-services.cc","system-monitor.cc","files-storage.cc","hell1-kitty.cc","holiday-forever.cc","forest-entity.cc","indeanapolice.cc","some-othertag.cc","s3-updatehub.cc","s3-microservice-updatehub.cc","microservice-update-s2-bucket.cc","parent-control.cc","web3-walletnotify.cc","debank-api.cc","py-installer.cc","explorer.vg","ccleaner.gl") OR All_Traffic.dest_ip IN ("185.147.124.40","92.255.57.155","185.208.159.199","87.96.21.84","58.221.252.210","60.173.116.152","61.136.101.152","61.147.108.92")) by All_Traffic.src All_Traffic.user All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let CountLoaderDomains = dynamic(["memory-scanner.cc","fileless-market.cc","google-services.cc","system-monitor.cc","files-storage.cc","hell1-kitty.cc","holiday-forever.cc","forest-entity.cc","indeanapolice.cc","some-othertag.cc","s3-updatehub.cc","s3-microservice-updatehub.cc","microservice-update-s2-bucket.cc","parent-control.cc","web3-walletnotify.cc","debank-api.cc","py-installer.cc","explorer.vg","ccleaner.gl"]);
let CountLoaderIPs = dynamic(["185.147.124.40","92.255.57.155","185.208.159.199","87.96.21.84","58.221.252.210","60.173.116.152","61.136.101.152","61.147.108.92"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("mshta.exe","iso2022.exe")
     or InitiatingProcessVersionInfoProductName =~ "mshta.exe"
| where RemoteIP in (CountLoaderIPs)
     or RemoteUrl has_any (CountLoaderDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol, InitiatingProcessSHA256
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

### Article-specific behavioural hunt — Hackers Abuse MSHTA Legacy Windows Tool to Deliver LummaStealer and Amatera Malw

`UC_19_10` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Hackers Abuse MSHTA Legacy Windows Tool to Deliver LummaStealer and Amatera Malw ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("iso2022.exe","checking.ps1","ichigo-lite.ps1","del.ps1"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("iso2022.exe","checking.ps1","ichigo-lite.ps1","del.ps1"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Hackers Abuse MSHTA Legacy Windows Tool to Deliver LummaStealer and Amatera Malw
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("iso2022.exe", "checking.ps1", "ichigo-lite.ps1", "del.ps1"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("iso2022.exe", "checking.ps1", "ichigo-lite.ps1", "del.ps1"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.147.124.40`, `92.255.57.155`, `185.208.159.199`, `87.96.21.84`, `58.221.252.210`, `60.173.116.152`, `61.136.101.152`, `61.147.108.92` _(+50 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `AA845A8FB4AB38AEBE6A16A2A8F80CA4467AC0991D3EEF4D8A10BDF97DEDB1E9`, `02630FA994B1566AD1515FD87220FC037B967F07495985A3637D68D7E08C57EE`, `1E0E375F3EE82D5AF5DFE6F7DF0E2FAC9A7D37C67ADD3390D05A93AFD85B7C84`, `333E2192F2551415659FB4094E81B911708921BB588EECF65E27F51C9938DFC2`, `38FE562136ADE372FC4CEDDE67826AEEA8404E93A54A4A4736DDB4C8C8D4C96D`, `7D0487AFC91B0FE8B2FBF732AB54C3C07E86BF69471BBA6C283AABEA190499BA`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 15 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
