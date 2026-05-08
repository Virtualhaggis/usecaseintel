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
This shift makes it clear that the attackers behind this campaign are actively e…

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
- **T1567** — Exfiltration Over Web Service
- **T1105** — Ingress Tool Transfer
- **T1497.001** — Virtualization/Sandbox Evasion: System Checks
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1047** — Windows Management Instrumentation
- **T1059** — Command and Scripting Interpreter
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] NWHStealer / Bun Loader C2 domain & file-hash sweep

`UC_18_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where (DNS.query IN ("whale-ether.pro","*.whale-ether.pro","cosmic-nebula.cc","*.cosmic-nebula.cc","silent-harvester.cc","*.silent-harvester.cc","silent-orbit.cc","*.silent-orbit.cc","support-onion.club","*.support-onion.club")) by DNS.src DNS.query | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.user) as user values(Processes.dest) as dest values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where Processes.process_hash IN ("d3a896f450561b2546b418b469a8e10949c7320212eb1c72b48e2b1e37c34ba5","96fe4ddfe256dc9d2c6faea7c18e2583cd9d9c0099a4ad2cf082f569ee8379f4","3710fb27d2032ef1eb1252ebf5c4dd516d2b2c0a83fb82c664c89e504b990fa9","33d07aa24b217f27df6a483295c817da198e12511a6989bcc6b917feaf8e491d","5427b4cefb329ed0e9585b3ce58a2788baf87e3b0c7221373f9bbd5f32c85b62","308da9f49ffa1d1744e428b567792ab22712159974e9da8d8e0414ecd81de93e","021838f30a43026084978bce187c165c6b640d8d474ec009d48078d21ec62025","c8e96b55f13435c4b43b7209d2403f1a0e0f9deb05edc50e0f777430be693b07","0614c4cc6375ab6bdcdd2dfa913a67d32c3e8be9b95a4a2aa09bb131b98191c8","0020999b2e3e4d1b2cfb69e4df9440d3ce05d508573889fdc12b724ce75a0cd8","0fa42df08cc467ec52b2d388b5575114a8ec067d13f6b1a653ec33fe879f88ca","15f79980650393d182f81cd6e389210568aa1f5f875e515efe6cb9485d64b7fb","20454ba58d509300fd694ae6159db4efa1b7ff965f98c29e7d087e20f96578c1") by Processes.dest Processes.process_name | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let nwh_domains = dynamic(["whale-ether.pro","cosmic-nebula.cc","silent-harvester.cc","silent-orbit.cc","support-onion.club"]);
let nwh_hashes = dynamic(["d3a896f450561b2546b418b469a8e10949c7320212eb1c72b48e2b1e37c34ba5","96fe4ddfe256dc9d2c6faea7c18e2583cd9d9c0099a4ad2cf082f569ee8379f4","3710fb27d2032ef1eb1252ebf5c4dd516d2b2c0a83fb82c664c89e504b990fa9","33d07aa24b217f27df6a483295c817da198e12511a6989bcc6b917feaf8e491d","5427b4cefb329ed0e9585b3ce58a2788baf87e3b0c7221373f9bbd5f32c85b62","308da9f49ffa1d1744e428b567792ab22712159974e9da8d8e0414ecd81de93e","021838f30a43026084978bce187c165c6b640d8d474ec009d48078d21ec62025","c8e96b55f13435c4b43b7209d2403f1a0e0f9deb05edc50e0f777430be693b07","0614c4cc6375ab6bdcdd2dfa913a67d32c3e8be9b95a4a2aa09bb131b98191c8","0020999b2e3e4d1b2cfb69e4df9440d3ce05d508573889fdc12b724ce75a0cd8","0fa42df08cc467ec52b2d388b5575114a8ec067d13f6b1a653ec33fe879f88ca","15f79980650393d182f81cd6e389210568aa1f5f875e515efe6cb9485d64b7fb","20454ba58d509300fd694ae6159db4efa1b7ff965f98c29e7d087e20f96578c1"]);
union isfuzzy=true
  ( DeviceNetworkEvents
      | where Timestamp > ago(30d)
      | where RemoteUrl has_any (nwh_domains)
         or tolower(RemoteUrl) endswith ".whale-ether.pro"
         or tolower(RemoteUrl) endswith ".cosmic-nebula.cc"
         or tolower(RemoteUrl) endswith ".silent-harvester.cc"
         or tolower(RemoteUrl) endswith ".silent-orbit.cc"
         or tolower(RemoteUrl) endswith ".support-onion.club"
      | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
                InitiatingProcessFileName, InitiatingProcessCommandLine,
                RemoteIP, RemotePort, RemoteUrl, Source="DeviceNetworkEvents" ),
  ( DeviceProcessEvents
      | where Timestamp > ago(30d)
      | where SHA256 in (nwh_hashes) or InitiatingProcessSHA256 in (nwh_hashes)
      | project Timestamp, DeviceName, AccountName, FileName, FolderPath,
                ProcessCommandLine, SHA256, Source="DeviceProcessEvents" ),
  ( DeviceFileEvents
      | where Timestamp > ago(30d)
      | where SHA256 in (nwh_hashes)
      | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName,
                FileName, FolderPath, SHA256, Source="DeviceFileEvents" )
| order by Timestamp desc
```

### [LLM] Bun Loader Installer.exe spawns sysreq.js-style WMI/CIM anti-VM probing

`UC_18_11` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmds values(Processes.process_path) as paths values(Processes.process_name) as children dc(Processes.process_name) as child_count from datamodel=Endpoint.Processes where Processes.parent_process_name="Installer.exe" (Processes.process_name IN ("powershell.exe","pwsh.exe","wmic.exe","WmiPrvSE.exe","cmd.exe")) (Processes.process IN ("*Win32_ComputerSystem*","*Win32_DiskDrive*","*Win32_VideoController*","*Win32_Processor*","*Win32_BIOS*","*CIM_ComputerSystem*","*Get-CimInstance*","*Get-WmiObject*","*Manufacturer*","*NumberOfCores*","*ScreenWidth*")) (Processes.parent_process_path IN ("*\\AppData\\Local\\Temp\\*","*\\Downloads\\*","*\\Users\\Public\\*","*\\AppData\\Roaming\\*")) by host Processes.user Processes.parent_process_path Processes.parent_process_id | where child_count >= 2 | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let probe_tokens = dynamic(["Win32_ComputerSystem","Win32_DiskDrive","Win32_VideoController","Win32_Processor","Win32_BIOS","CIM_ComputerSystem","Get-CimInstance","Get-WmiObject","Manufacturer","NumberOfCores","NumberOfLogicalProcessors","ScreenWidth","CurrentHorizontalResolution"]);
let vm_install_paths = dynamic([@"\AppData\Local\Temp\",@"\Downloads\",@"\Users\Public\",@"\AppData\Roaming\",@"\AppData\Local\Packages\"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName =~ "Installer.exe"
| where InitiatingProcessFolderPath has_any (vm_install_paths)
| where FileName in~ ("powershell.exe","pwsh.exe","wmic.exe","cmd.exe","WmiPrvSE.exe")
| where ProcessCommandLine has_any (probe_tokens)
| summarize ProbeCount = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            ProbeTokens = make_set(extract(@"(?i)(Win32_\w+|Get-CimInstance|Get-WmiObject|Manufacturer|NumberOfCores|ScreenWidth)", 1, ProcessCommandLine), 32),
            SampleCmds = make_set(ProcessCommandLine, 8),
            ParentPath = any(InitiatingProcessFolderPath),
            ParentSHA256 = any(InitiatingProcessSHA256)
            by DeviceName, AccountName, InitiatingProcessId, bin(Timestamp, 5m)
| where ProbeCount >= 3                              // sysreq.js fires multiple WMI queries to score VM-ness
| order by FirstSeen desc
```

### [LLM] NWHStealer fallback loader: dw.exe executed from extracted ZIP \DW\ folder

`UC_18_12` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.process_hash) as hash values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name="dw.exe" (Processes.process_path IN ("*\\DW\\dw.exe","*\\AppData\\Local\\Temp\\*\\DW\\dw.exe","*\\Downloads\\*\\DW\\dw.exe","*\\Users\\Public\\*\\DW\\dw.exe","*\\AppData\\Roaming\\*\\DW\\dw.exe")) (Processes.parent_process_name IN ("explorer.exe","7zG.exe","7zFM.exe","WinRAR.exe","Rar.exe","cmd.exe","powershell.exe")) by host Processes.user Processes.process_path Processes.parent_process_path | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let suspicious_parents = dynamic(["explorer.exe","7zG.exe","7zFM.exe","WinRAR.exe","Rar.exe","cmd.exe","powershell.exe","pwsh.exe"]);
let exec_paths = dynamic([@"\AppData\Local\Temp\",@"\Downloads\",@"\Users\Public\",@"\AppData\Roaming\",@"\Desktop\"]);
let dw_proc =
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where AccountName !endswith "$"
    | where FileName =~ "dw.exe"
    | where FolderPath has @"\DW\"
    | where FolderPath has_any (exec_paths)
    | where InitiatingProcessFileName in~ (suspicious_parents)
    | project Timestamp, DeviceName, AccountName, FolderPath, SHA256,
              ProcessCommandLine, InitiatingProcessFileName,
              InitiatingProcessCommandLine, ProcessId;
// Pivot: was a Readme.txt dropped in the same archive folder within 1h?
let readme_drops =
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where ActionType == "FileCreated"
    | where FileName =~ "Readme.txt"
    | project ReadmeTime = Timestamp, DeviceName, ReadmeFolder = FolderPath;
dw_proc
| join kind=leftouter readme_drops on DeviceName
| where isempty(ReadmeFolder)
    or (ReadmeTime between (Timestamp - 1h .. Timestamp + 5m)
        and tostring(split(ReadmeFolder, @"\")[-2]) =~ tostring(split(FolderPath, @"\")[-2]))
| project Timestamp, DeviceName, AccountName, FolderPath, SHA256,
          ProcessCommandLine, InitiatingProcessFileName,
          ReadmeTime, ReadmeFolder
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

`UC_18_9` · phase: **exploit** · confidence: **High**

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
