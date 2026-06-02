# [HIGH] Iranian Hackers Deploy MiniFast and MiniJunk V2 via Phishing and SEO Poisoning

**Source:** The Hacker News
**Published:** 2026-05-26
**Article:** https://thehackernews.com/2026/05/iranian-hackers-deploy-minifast-and.html

## Threat Profile

Iranian Hackers Deploy MiniFast and MiniJunk V2 via Phishing and SEO Poisoning 
 Ravie Lakshmanan  May 26, 2026 Cyber Espionage / Artificial Intelligence 
The Iranian state-sponsored threat actor known as Nimbus Manticore (aka Screening Serpens and UNC1549 ) has been attributed to a fresh campaign using lures impersonating organizations in the aviation and software sectors across the U.S., Europe, and the Middle East following the joint U.S.-Israeli military campaign against the country in lat…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `getsqldeveloper.com`
- **Domain (defanged):** `business-startup.org`
- **Domain (defanged):** `buisness-centeral-transportation.com`
- **Domain (defanged):** `premierhealthadvisory.com`
- **Domain (defanged):** `ramiltonsfinance.com`
- **SHA256:** `10fd541674adadfbba99b54280f7e59732746faf2b10ce68521866f737f1e46d`
- **SHA256:** `eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71`
- **SHA256:** `781605ce9d4a9869e846f6c9657d71437cb6240ab27ffbc4cd550c0e06996690`
- **SHA256:** `2c214494fd0bad31473ca8adce78a4f50847876584571e66aadeae70827ec2dc`
- **SHA256:** `f08b17856616d66492a24dced27f788e235f35f42fa7cd10f315000d3a2f4c03`
- **SHA256:** `a57ffb819fe8d98ff925c5d7b239598fe302acf5a13193d7a535040a71298fdf`
- **SHA256:** `63d0d3c4a7f71bdbca720903d6a99b832089cc093c64d2938e7e001e56c17ab4`
- **SHA256:** `74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27`
- **SHA256:** `bc3b44154518c5794ce639108e7b9c5fecb0c189607a26de1aaed518d890c7ad`
- **SHA256:** `ecaf493c320d201d285ef5f61d75744216e47cf1115b4af528f9a78883cc446e`
- **SHA256:** `44f4f7aca7f1d9bfdaf7b3736934cbe19f851a707662f8f0b0c49b383e054250`
- **SHA256:** `0db36a04d304ad96f9e6f97b531934594cd95a5cea9ff2c9af249201089dc864`
- **SHA256:** `485f182f7b74ee4013b2539275a95d21e3a9bf0082c331937af9353a324b36f3`
- **SHA256:** `64530d7e6ee30e4a66d9eeed6b8595c33fd72f5f73409133ca40539e5695df4c`
- **SHA256:** `332ba2f0297dfb1599adecc3e9067893e7cf243aa23aedce4906a4c480574c17`
- **SHA256:** `9e4a658e6d831c9e9bdfe11884a75b7c64812ed0a80e8495ddf6b316505acac1`
- **SHA256:** `43dc62cef52ebdd69e79f10015b3e13890f26c058325c0ff139c70f8d8eadcfa`
- **SHA256:** `8808c794c24367438f183e4be941876f1d3ecd0c8d2eb43b10d2380841d2283b`
- **SHA256:** `5c3362d20229597d11380f56d1f2eb39647fb6afad7be8392a7abcd18dff12f8`
- **SHA256:** `0291ef318576953f7f3fe287e7775ed1d7c3206119dc7b9cd6d85c02779e6e40`
- **SHA256:** `d4a7e9f107fe40c1a5d0139c6c6e25bf6bf57f61feff090bee28f476bb3cc3c2`
- **SHA256:** `38bd137c672bd58d08c4f0502f993a6561e2c3411773d1ae57ee0151a0a9d11d`
- **SHA256:** `f54cd38632ac9da3af3533ae93e92625cbcb04df521dbf1b6acfaa81218f9e8c`
- **SHA256:** `b19e06da580cf91691eda066ac9ee4b09c6e5dc26c367af12660fe1f9306eec4`
- **SHA256:** `9cf029daca89523d917dafed0568d11d00e45ec96b5b90b4a1f7fd4018c7da84`
- **SHA256:** `a13ba3c5aff46e9daf2d23df4b3e3d49dc7236c207c56f0a1433051f3450d441`
- **SHA256:** `dfa1e3137a032ee8561a1cd5e1a0f71a10bebb36aef7c336c878638a9c1239ee`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1053.005** — Scheduled Task
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1574.014** — Hijack Execution Flow: AppDomainManager
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1608.006** — Stage Capabilities: SEO Poisoning
- **T1566.002** — Phishing: Spearphishing Link

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Nimbus Manticore AppDomainManager hijack — .exe.config dropped beside benign sig

`UC_118_10` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="*.exe.config" (Filesystem.file_path="*Downloads*" OR Filesystem.file_path="*AppData*" OR Filesystem.file_path="*Temp*" OR Filesystem.file_path="*Public*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName endswith ".exe.config"
| where FolderPath has_any ("Downloads","AppData","Temp","Public")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] Nimbus Manticore AppDomain hijack — signed .NET binary loads DLL from user-writable dir

`UC_118_11` · phase: **exploit** · confidence: **Medium**

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where FileName endswith ".dll"
| where FolderPath has_any ("Downloads","AppData\\Local\\Temp","Temp","Public")
| where InitiatingProcessFolderPath has_any ("Downloads","AppData","Temp","Public")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, LoadedDll=FileName, LoadedDllPath=FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Nimbus Manticore / MiniFast C2 beacon to campaign domains

`UC_118_12` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query IN ("getsqldeveloper.com","business-startup.org","buisness-centeral-transportation.com","premierhealthadvisory.com","ramiltonsfinance.com") by DNS.src DNS.dest DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("getsqldeveloper.com","business-startup.org","buisness-centeral-transportation.com","premierhealthadvisory.com","ramiltonsfinance.com")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] MiniFast / MiniJunk V2 payload execution by SHA256

`UC_118_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("10fd541674adadfbba99b54280f7e59732746faf2b10ce68521866f737f1e46d","eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71","781605ce9d4a9869e846f6c9657d71437cb6240ab27ffbc4cd550c0e06996690","2c214494fd0bad31473ca8adce78a4f50847876584571e66aadeae70827ec2dc","f08b17856616d66492a24dced27f788e235f35f42fa7cd10f315000d3a2f4c03","a57ffb819fe8d98ff925c5d7b239598fe302acf5a13193d7a535040a71298fdf","63d0d3c4a7f71bdbca720903d6a99b832089cc093c64d2938e7e001e56c17ab4","74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let iocs = dynamic(["10fd541674adadfbba99b54280f7e59732746faf2b10ce68521866f737f1e46d","eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71","781605ce9d4a9869e846f6c9657d71437cb6240ab27ffbc4cd550c0e06996690","2c214494fd0bad31473ca8adce78a4f50847876584571e66aadeae70827ec2dc","f08b17856616d66492a24dced27f788e235f35f42fa7cd10f315000d3a2f4c03","a57ffb819fe8d98ff925c5d7b239598fe302acf5a13193d7a535040a71298fdf","63d0d3c4a7f71bdbca720903d6a99b832089cc093c64d2938e7e001e56c17ab4","74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27"]);
union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where SHA256 in~ (iocs)
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, ProcessCommandLine
| order by Timestamp desc
```

### [LLM] Nimbus Manticore trojanized SQL Developer / Zoom installer download & execution

`UC_118_14` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*getsqldeveloper.com*" OR Web.url="*business-startup.org*" OR Web.url="*buisness-centeral-transportation.com*" OR Web.url="*premierhealthadvisory.com*" OR Web.url="*ramiltonsfinance.com*") by Web.src Web.dest Web.url Web.http_user_agent | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileOriginUrl has_any ("getsqldeveloper.com","business-startup.org","buisness-centeral-transportation.com","premierhealthadvisory.com","ramiltonsfinance.com")
   or (FileName has_any ("sqldeveloper","sql_developer","zoom") and (FileName endswith ".exe" or FileName endswith ".msi" or FileName endswith ".zip") and FolderPath has_any ("Downloads","Temp"))
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath, FileOriginUrl, SHA256
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
  - IP / domain IOC(s): `getsqldeveloper.com`, `business-startup.org`, `buisness-centeral-transportation.com`, `premierhealthadvisory.com`, `ramiltonsfinance.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `10fd541674adadfbba99b54280f7e59732746faf2b10ce68521866f737f1e46d`, `eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71`, `781605ce9d4a9869e846f6c9657d71437cb6240ab27ffbc4cd550c0e06996690`, `2c214494fd0bad31473ca8adce78a4f50847876584571e66aadeae70827ec2dc`, `f08b17856616d66492a24dced27f788e235f35f42fa7cd10f315000d3a2f4c03`, `a57ffb819fe8d98ff925c5d7b239598fe302acf5a13193d7a535040a71298fdf`, `63d0d3c4a7f71bdbca720903d6a99b832089cc093c64d2938e7e001e56c17ab4`, `74882085db2088356ed7f72f01e0404a0a98cda88ef56fb15ce74c1f36b26d27` _(+19 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 15 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
