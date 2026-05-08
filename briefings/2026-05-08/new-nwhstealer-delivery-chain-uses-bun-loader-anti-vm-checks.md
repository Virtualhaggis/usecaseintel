# [HIGH] New NWHStealer Delivery Chain Uses Bun Loader, Anti-VM Checks, and Encrypted C2

**Source:** Cyber Security News
**Published:** 2026-05-08
**Article:** https://cybersecuritynews.com/new-nwhstealer-delivery-chain-uses-bun-loader/

## Threat Profile

Home Cyber Security News 
New NWHStealer Delivery Chain Uses Bun Loader, Anti-VM Checks, and Encrypted C2 
By Tushar Subhra Dutta 
May 8, 2026 




A new and evolving threat has caught the attention of cybersecurity researchers worldwide. A Windows-based information stealer known as NWHStealer has resurfaced with a more sophisticated delivery chain, now using the Bun JavaScript runtime as part of its infection process. 
This shift makes it clear that the attackers behind this campaign are ac…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `whale-ether.pro`
- **Domain (defanged):** `cosmic-nebula.cc`
- **Domain (defanged):** `silent-harvester.cc`
- **Domain (defanged):** `silent-orbit.cc`
- **Domain (defanged):** `support-onion.club`
- **SHA256:** `d3a896f450561b2546b418b469a8e10949c7320212eb1c72b48e2b1e37c34ba5`
- **SHA256:** `96fe4ddfe256dc9d2c6faea7c18e2583cd9d9c0099a4ad2cf082f569ee8379f4`
- **SHA256:** `3710fb27d2032ef1eb1252ebf5c4dd516d2b2c0a83fb82c664c89e504b990fa9`
- **SHA256:** `33d07aa24b217f27df6a483295c817da198e12511a6989bcc6b917feaf8e491d`
- **SHA256:** `5427b4cefb329ed0e9585b3ce58a2788baf87e3b0c7221373f9bbd5f32c85b62`
- **SHA256:** `308da9f49ffa1d1744e428b567792ab22712159974e9da8d8e0414ecd81de93e`
- **SHA256:** `021838f30a43026084978bce187c165c6b640d8d474ec009d48078d21ec62025`
- **SHA256:** `c8e96b55f13435c4b43b7209d2403f1a0e0f9deb05edc50e0f777430be693b07`
- **SHA256:** `0614c4cc6375ab6bdcdd2dfa913a67d32c3e8be9b95a4a2aa09bb131b98191c8`
- **SHA256:** `0020999b2e3e4d1b2cfb69e4df9440d3ce05d508573889fdc12b724ce75a0cd8`
- **SHA256:** `0fa42df08cc467ec52b2d388b5575114a8ec067d13f6b1a653ec33fe879f88ca`
- **SHA256:** `15f79980650393d182f81cd6e389210568aa1f5f875e515efe6cb9485d64b7fb`
- **SHA256:** `20454ba58d509300fd694ae6159db4efa1b7ff965f98c29e7d087e20f96578c1`

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
- **T1027** — Obfuscated Files or Information
- **T1053.005** — Persistence (article-specific)
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1568** — Dynamic Resolution
- **T1497.001** — Virtualization/Sandbox Evasion: System Checks
- **T1082** — System Information Discovery
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1047** — Windows Management Instrumentation
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] NWHStealer / Bun Loader C2 domain contact (whale-ether, cosmic-nebula, silent-harvester, silent-orbit, support-onion)

`UC_4_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution where (Network_Resolution.query="*whale-ether.pro" OR Network_Resolution.query="*cosmic-nebula.cc" OR Network_Resolution.query="*silent-harvester.cc" OR Network_Resolution.query="*silent-orbit.cc" OR Network_Resolution.query="*support-onion.club") by Network_Resolution.src Network_Resolution.dest Network_Resolution.query Network_Resolution.answer host
| `drop_dm_object_name(Network_Resolution)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| append [| tstats summariesonly=true count from datamodel=Web where (Web.url="*whale-ether.pro*" OR Web.url="*cosmic-nebula.cc*" OR Web.url="*silent-harvester.cc*" OR Web.url="*silent-orbit.cc*" OR Web.url="*support-onion.club*") by Web.src Web.dest Web.url Web.user | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
let _c2_domains = dynamic(["whale-ether.pro","cosmic-nebula.cc","silent-harvester.cc","silent-orbit.cc","support-onion.club"]);
union isfuzzy=true
( DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl has_any (_c2_domains)
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, Source = "NetworkEvent"),
( DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
    | where QueryName has_any (_c2_domains)
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl = QueryName, Source = "DnsQuery")
| order by Timestamp desc
```

### [LLM] Bun-bundled Installer.exe spawning PowerShell/WMIC for NWHStealer anti-VM hardware enumeration (sysreq.js)

`UC_4_11` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.parent_process_name="Installer.exe" (Processes.parent_process_path="*\\Temp\\*" OR Processes.parent_process_path="*\\Downloads\\*" OR Processes.parent_process_path="*\\AppData\\Local\\Temp\\*" OR Processes.parent_process_path="*\\Desktop\\*" OR Processes.parent_process_path="*\\Public\\*") (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="wmic.exe" OR Processes.process_name="cmd.exe" OR Processes.process_name="cscript.exe") (Processes.process="*Win32_ComputerSystem*" OR Processes.process="*Win32_Processor*" OR Processes.process="*Win32_LogicalDisk*" OR Processes.process="*Win32_DiskDrive*" OR Processes.process="*Win32_DesktopMonitor*" OR Processes.process="*Win32_VideoController*" OR Processes.process="*computersystem*" OR Processes.process="*diskdrive*" OR Processes.process="*desktopmonitor*" OR Processes.process="*Manufacturer*" OR Processes.process="*NumberOfCores*") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_path Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _staging_paths = dynamic([@"\Temp\", @"\Downloads\", @"\AppData\Local\Temp\", @"\Desktop\", @"\Public\", @"\Users\Public\"]);
let _wmi_classes = dynamic(["Win32_ComputerSystem","Win32_Processor","Win32_LogicalDisk","Win32_DiskDrive","Win32_DesktopMonitor","Win32_VideoController","Win32_BIOS","computersystem","diskdrive","desktopmonitor","Manufacturer","NumberOfCores"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "Installer.exe"
| where InitiatingProcessFolderPath has_any (_staging_paths)
| where FileName in~ ("powershell.exe","pwsh.exe","wmic.exe","cmd.exe","cscript.exe")
| where ProcessCommandLine has_any (_wmi_classes)
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentSHA256 = InitiatingProcessSHA256,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          ChildSHA256 = SHA256
| order by Timestamp desc
```

### [LLM] NWHStealer fallback loader 'dw.exe' executed from \DW\ subfolder or matching disclosed SHA-256

`UC_4_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="dw.exe" AND (Processes.process_path="*\\DW\\dw.exe" OR Processes.parent_process_path="*\\DW\\*")) OR Processes.process_hash IN ("d3a896f450561b2546b418b469a8e10949c7320212eb1c72b48e2b1e37c34ba5","96fe4ddfe256dc9d2c6faea7c18e2583cd9d9c0099a4ad2cf082f569ee8379f4","3710fb27d2032ef1eb1252ebf5c4dd516d2b2c0a83fb82c664c89e504b990fa9","33d07aa24b217f27df6a483295c817da198e12511a6989bcc6b917feaf8e491d","5427b4cefb329ed0e9585b3ce58a2788baf87e3b0c7221373f9bbd5f32c85b62","308da9f49ffa1d1744e428b567792ab22712159974e9da8d8e0414ecd81de93e","021838f30a43026084978bce187c165c6b640d8d474ec009d48078d21ec62025","c8e96b55f13435c4b43b7209d2403f1a0e0f9deb05edc50e0f777430be693b07") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process Processes.process_path Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let _nwh_hashes = dynamic([
    "d3a896f450561b2546b418b469a8e10949c7320212eb1c72b48e2b1e37c34ba5",
    "96fe4ddfe256dc9d2c6faea7c18e2583cd9d9c0099a4ad2cf082f569ee8379f4",
    "3710fb27d2032ef1eb1252ebf5c4dd516d2b2c0a83fb82c664c89e504b990fa9",
    "33d07aa24b217f27df6a483295c817da198e12511a6989bcc6b917feaf8e491d",
    "5427b4cefb329ed0e9585b3ce58a2788baf87e3b0c7221373f9bbd5f32c85b62",
    "308da9f49ffa1d1744e428b567792ab22712159974e9da8d8e0414ecd81de93e",
    "021838f30a43026084978bce187c165c6b640d8d474ec009d48078d21ec62025",
    "c8e96b55f13435c4b43b7209d2403f1a0e0f9deb05edc50e0f777430be693b07"]);
union isfuzzy=true
( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where (FileName =~ "dw.exe" and FolderPath has @"\DW\")
        or SHA256 in (_nwh_hashes)
        or InitiatingProcessSHA256 in (_nwh_hashes)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
              ProcessCommandLine,
              Parent = InitiatingProcessFileName,
              ParentPath = InitiatingProcessFolderPath,
              ParentSHA256 = InitiatingProcessSHA256,
              Source = "Process"),
( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileCreated","FileModified","FileRenamed")
    | where (FileName =~ "dw.exe" and FolderPath has @"\DW\")
        or SHA256 in (_nwh_hashes)
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, FileName, FolderPath, SHA256,
              ProcessCommandLine = InitiatingProcessCommandLine,
              Parent = InitiatingProcessFileName,
              ParentPath = InitiatingProcessFolderPath,
              ParentSHA256 = InitiatingProcessSHA256,
              Source = "FileWrite")
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

### Article-specific behavioural hunt — New NWHStealer Delivery Chain Uses Bun Loader, Anti-VM Checks, and Encrypted C2

`UC_4_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New NWHStealer Delivery Chain Uses Bun Loader, Anti-VM Checks, and Encrypted C2 ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","sysreq.js","memload.js","dw.exe","next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","sysreq.js","memload.js","dw.exe","next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New NWHStealer Delivery Chain Uses Bun Loader, Anti-VM Checks, and Encrypted C2
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "sysreq.js", "memload.js", "dw.exe", "next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "sysreq.js", "memload.js", "dw.exe", "next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `whale-ether.pro`, `cosmic-nebula.cc`, `silent-harvester.cc`, `silent-orbit.cc`, `support-onion.club`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `d3a896f450561b2546b418b469a8e10949c7320212eb1c72b48e2b1e37c34ba5`, `96fe4ddfe256dc9d2c6faea7c18e2583cd9d9c0099a4ad2cf082f569ee8379f4`, `3710fb27d2032ef1eb1252ebf5c4dd516d2b2c0a83fb82c664c89e504b990fa9`, `33d07aa24b217f27df6a483295c817da198e12511a6989bcc6b917feaf8e491d`, `5427b4cefb329ed0e9585b3ce58a2788baf87e3b0c7221373f9bbd5f32c85b62`, `308da9f49ffa1d1744e428b567792ab22712159974e9da8d8e0414ecd81de93e`, `021838f30a43026084978bce187c165c6b640d8d474ec009d48078d21ec62025`, `c8e96b55f13435c4b43b7209d2403f1a0e0f9deb05edc50e0f777430be693b07` _(+5 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 13 use case(s) fired, 23 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
