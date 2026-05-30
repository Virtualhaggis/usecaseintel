# [CRIT] GREYVIBE Hackers Leverage ChatGPT and Google Gemini to Fuel Cyberattacks

**Source:** Cyber Security News
**Published:** 2026-05-30
**Article:** https://cybersecuritynews.com/greyvibe-hackers-chatgpt-and-google-gemini/

## Threat Profile

Home Cyber Security News 
GREYVIBE Hackers Leverage ChatGPT and Google Gemini to Fuel Cyberattacks 
By Abinaya 
May 30, 2026 




GREYVIBE hackers are increasingly leveraging generative AI tools such as ChatGPT and Google Gemini to enhance cyberattack operations.
The campaign, active since at least August 2025, primarily targets Ukraine and related entities across the government, military, and civilian sectors, highlighting a growing convergence between artificial intelligence and modern cyb…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `89.37.185.60`
- **IPv4 (defanged):** `74.112.102.120`
- **IPv4 (defanged):** `194.87.128.243`
- **IPv4 (defanged):** `194.87.108.110`
- **IPv4 (defanged):** `89.125.189.118`
- **IPv4 (defanged):** `89.125.189.85`
- **IPv4 (defanged):** `91.149.221.124`
- **Domain (defanged):** `lapas.live`
- **Domain (defanged):** `zoomconference.click`
- **Domain (defanged):** `zoomconference.app`
- **Domain (defanged):** `princess-mens.fun`
- **Domain (defanged):** `princess-mens-club.com`
- **Domain (defanged):** `princess-mens.click`
- **Domain (defanged):** `princessclub.click`
- **Domain (defanged):** `princessclub.best`
- **Domain (defanged):** `princessclub.online`
- **Domain (defanged):** `princessclub.cyou`
- **Domain (defanged):** `clubprincess.click`
- **Domain (defanged):** `strip-mens.tilda.ws`
- **Domain (defanged):** `frontforce.org`
- **Domain (defanged):** `ukrguard.org`
- **Domain (defanged):** `ukrbezpeka.online`
- **Domain (defanged):** `ironbrave.online`
- **Domain (defanged):** `ukrvarta.online`
- **Domain (defanged):** `edbo.linkpc.net`
- **Domain (defanged):** `dsszzi.linkpc.net`
- **Domain (defanged):** `goodhillsenterprise.com`
- **Domain (defanged):** `ny-car-dealership.it.com`
- **Domain (defanged):** `doct0rsim.com`
- **Domain (defanged):** `routinesyscheckup.com`
- **Domain (defanged):** `serotoninenterprise.com`
- **Domain (defanged):** `nycpartnersenterprise.com`
- **Domain (defanged):** `chiselworksenterprise.com`
- **Domain (defanged):** `newrentalsenterprise.com`
- **Domain (defanged):** `j4jobspk.com`
- **Domain (defanged):** `storage.vlasiuk.kiev.ua`
- **Domain (defanged):** `share.secureinfo.eu`
- **SHA256:** `476334f9254ef0277b3462b6086655f38358a983b95991cfe4dcdd787740906a`
- **SHA256:** `78773eb9738bc3306a56bf39adc8212226479c24af8bf453be9d57103a91a904`
- **SHA256:** `62b585f36d4b14fa1e036feed692267aa098e7fc6cabb468a07997a025309299`
- **SHA256:** `d60dd96ef92b43e2e4f955dd76448fc320c3f8445b661d9a4a3c40caca0aa8a5`
- **SHA256:** `687629ca9dc5b9b4bdf6c06fb1405449638b905f3a0c08bccac1c519ef22964d`
- **SHA256:** `8a7401444dd7c85b36ff7b1d0b36c5953692ef32dbeac7642fb7c1034bd8a726`
- **SHA256:** `e81af6ae6862d905d8634a1f6e0a8893ba28e3ce61d12ccac020ef6fae802e8b`
- **SHA256:** `93111e523c38d98247a78a0d1d9ae163e9874acb70721f6fe0bf451c62fff283`
- **SHA256:** `c823a315c2c78d2fd345c9b38bb7fc31a8cbff96c534ce9cc66c4e54bc7935a2`
- **SHA256:** `5115eca388860371d994457793f3a3c2c3d106da48ca12ecccb9432522c56cc3`
- **SHA256:** `bd3f35b91bf83427e953d4cf531a0ee4b5ec9fc76b91700274effe0eba22510f`
- **SHA256:** `2abb318455960b446d034967c8403ec4339ba248b946f02cb1307ed7e6f4e327`

## MITRE ATT&CK Techniques

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
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol
- **T1059.003** — Windows Command Shell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1095** — Non-Application Layer Protocol
- **T1189** — Drive-by Compromise
- **T1583.001** — Acquire Infrastructure: Domains
- **T1005** — Data from Local System
- **T1119** — Automated Collection
- **T1036** — Masquerading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GREYVIBE fake-CAPTCHA ClickFix: explorer→powershell from Run dialog

`UC_1_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="explorer.exe" (Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe")) (Processes.process IN ("*iex*","*Invoke-Expression*","*DownloadString*","*IWR *","*Invoke-WebRequest*","*curl *","*-EncodedCommand*","*FromBase64String*","*WebClient*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe")
| where ProcessCommandLine has_any ("IEX","Invoke-Expression","DownloadString","Invoke-WebRequest","IWR ","-EncodedCommand","FromBase64String","WebClient","curl ","mshta http","mshta hxxp")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] GREYVIBE C2 callback to known PhantomRelay / FallSpy IPs

`UC_1_13` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("89.37.185.60","74.112.102.120","194.87.128.243","194.87.108.110","89.125.189.118","89.125.189.85","91.149.221.124") by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GreyvibeIPs = dynamic(["89.37.185.60","74.112.102.120","194.87.128.243","194.87.108.110","89.125.189.118","89.125.189.85","91.149.221.124"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (GreyvibeIPs)
| project Timestamp, DeviceName, RemoteIP, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] GREYVIBE adult-club & Zoom lure domain resolution

`UC_1_14` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("lapas.live","zoomconference.click","zoomconference.app","princess-mens.fun","princess-mens-club.com","princess-mens.click","princessclub.click","princessclub.best") OR DNS.query="*.princess-mens.fun" OR DNS.query="*.princessclub.best" by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let LureDomains = dynamic(["lapas.live","zoomconference.click","zoomconference.app","princess-mens.fun","princess-mens-club.com","princess-mens.click","princessclub.click","princessclub.best"]);
let LureRegex = @"(?i)(lapas\.live|zoomconference\.(click|app)|princess-mens(-club)?\.(fun|com|click)|princessclub\.(click|best))";
union isfuzzy=true
(DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl matches regex LureRegex
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, RemoteUrl, RemoteIP, InitiatingProcessFileName, Source="DeviceNetworkEvents"),
(UrlClickEvents
    | where Timestamp > ago(30d)
    | where Url matches regex LureRegex
    | project Timestamp, DeviceName="", AccountName=AccountUpn, RemoteUrl=Url, RemoteIP=IPAddress, InitiatingProcessFileName="", Source="UrlClickEvents"),
(EmailUrlInfo
    | where Timestamp > ago(30d)
    | where Url matches regex LureRegex
    | project Timestamp, DeviceName="", AccountName="", RemoteUrl=Url, RemoteIP="", InitiatingProcessFileName="", Source="EmailUrlInfo")
| order by Timestamp desc
```

### [LLM] LegionRelay PowerShell collecting Telegram/Signal messaging data

`UC_1_15` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("powershell.exe","pwsh.exe") (Filesystem.file_path="*\\Telegram Desktop\\tdata\\*" OR Filesystem.file_path="*\\Signal\\sql\\*" OR Filesystem.file_path="*\\Signal\\attachments.noindex\\*" OR Filesystem.file_path="*\\AppData\\Roaming\\Telegram Desktop\\*") by Filesystem.dest Filesystem.user Filesystem.process_name | where count > 5 | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
| where FolderPath has_any ("\\Telegram Desktop\\tdata\\","\\AppData\\Roaming\\Telegram Desktop\\","\\Signal\\sql\\","\\Signal\\attachments.noindex\\","\\AppData\\Roaming\\Signal\\")
| where ActionType in ("FileCreated","FileModified","FileRenamed","FileOpened")
| summarize FileCount=dcount(FolderPath), Files=make_set(FolderPath, 25), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessId
| where FileCount > 3
| order by LastSeen desc
```

### [LLM] PhantomRelay PowerShell WebSocket C2

`UC_1_16` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") (Processes.process="*ClientWebSocket*" OR Processes.process="*System.Net.WebSockets*" OR Processes.process="*ws://*" OR Processes.process="*wss://*" OR Processes.process="*MemoryStream*WebSocket*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("ClientWebSocket","System.Net.WebSockets","ws://","wss://","WebSocketCreate")
| where InitiatingProcessFileName !in~ ("devenv.exe","code.exe","vsdbg.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Archive from Google Drive followed by decoy doc + loader execution

`UC_1_17` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("winrar.exe","7zg.exe","7zfm.exe","explorer.exe") (Processes.process_path="*\\Downloads\\*" OR Processes.process_path="*\\Temp\\*") (Processes.process_name IN ("powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","cmd.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let GreyvibeHashes = dynamic(["476334f9254ef0277b3462b6086655f38358a983b95991cfe4dcdd787740906a","78773eb9738bc3306a56bf39adc8212226479c24af8bf453be9d57103a91a904","62b585f36d4b14fa1e036feed692267aa098e7fc6cabb468a07997a025309299","d60dd96ef92b43e2e4f955dd76448fc320c3f8445b661d9a4a3c40caca0aa8a5","687629ca9dc5b9b4bdf6c06fb1405449638b905f3a0c08bccac1c519ef22964d","8a7401444dd7c85b36ff7b1d0b36c5953692ef32dbeac7642fb7c1034bd8a726","e81af6ae6862d905d8634a1f6e0a8893ba28e3ce61d12ccac020ef6fae802e8b","93111e523c38d98247a78a0d1d9ae163e9874acb70721f6fe0bf451c62fff283"]);
let ArchiveDrops = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z" or FileName endswith ".iso"
    | where FileOriginUrl has_any ("drive.google.com","drive.usercontent.google.com","docs.google.com")
    | project DropTime=Timestamp, DeviceName, ArchiveFolder=FolderPath, ArchiveFile=FileName, DownloadUrl=FileOriginUrl;
let SuspiciousChildren = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName in~ ("winrar.exe","7zg.exe","7zfm.exe","explorer.exe")
    | where FileName in~ ("powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","cmd.exe")
        or SHA256 in (GreyvibeHashes)
    | project ProcTime=Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, SHA256;
ArchiveDrops
| join kind=inner SuspiciousChildren on DeviceName
| where ProcTime between (DropTime .. DropTime + 30m)
| project DropTime, ProcTime, DelayMin=datetime_diff("minute", ProcTime, DropTime), DeviceName, AccountName, ArchiveFile, DownloadUrl, FileName, ProcessCommandLine, SHA256
| order by ProcTime desc
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
  - IP / domain IOC(s): `89.37.185.60`, `74.112.102.120`, `194.87.128.243`, `194.87.108.110`, `89.125.189.118`, `89.125.189.85`, `91.149.221.124`, `lapas.live` _(+29 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `476334f9254ef0277b3462b6086655f38358a983b95991cfe4dcdd787740906a`, `78773eb9738bc3306a56bf39adc8212226479c24af8bf453be9d57103a91a904`, `62b585f36d4b14fa1e036feed692267aa098e7fc6cabb468a07997a025309299`, `d60dd96ef92b43e2e4f955dd76448fc320c3f8445b661d9a4a3c40caca0aa8a5`, `687629ca9dc5b9b4bdf6c06fb1405449638b905f3a0c08bccac1c519ef22964d`, `8a7401444dd7c85b36ff7b1d0b36c5953692ef32dbeac7642fb7c1034bd8a726`, `e81af6ae6862d905d8634a1f6e0a8893ba28e3ce61d12ccac020ef6fae802e8b`, `93111e523c38d98247a78a0d1d9ae163e9874acb70721f6fe0bf451c62fff283` _(+4 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 18 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
