# [HIGH] Turla Turns Kazuar Backdoor Into Modular P2P Botnet for Persistent Access

**Source:** The Hacker News
**Published:** 2026-05-15
**Article:** https://thehackernews.com/2026/05/turla-turns-kazuar-backdoor-into.html

## Threat Profile

Turla Turns Kazuar Backdoor Into Modular P2P Botnet for Persistent Access 
 Ravie Lakshmanan  May 15, 2026 Botnet / Threat Intelligence 
The Russian state-sponsored hacking group known as
Turla 
has transformed its custom backdoor Kazuar into a modular peer-to-peer (P2P) botnet that's engineered for stealth and persistent access to compromised hosts.
Turla, per the U.S. Cybersecurity and Infrastructure Security Agency (CISA), is assessed to be affiliated with Center 16 of Russia's Federal Secu…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4`
- **SHA256:** `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9`
- **SHA256:** `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d`
- **SHA256:** `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1140** — Deobfuscate/Decode Files or Information
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1090** — Proxy
- **T1114.001** — Email Collection: Local Email Collection
- **T1056.001** — Input Capture: Keylogging
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1074.001** — Data Staged: Local Data Staging
- **T1560.001** — Archive Collected Data: Archive via Utility
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Pelmeni / ShadowLoader dropper SHA256 hash match on disk or execution

`UC_121_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_hash IN ("69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85") by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_hash Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let BadHashes = dynamic(["69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85"]);
union isfuzzy=true
  (DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (BadHashes) or InitiatingProcessSHA256 in (BadHashes)
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256, Src="ProcessExec"),
  (DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (BadHashes)
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, FolderPath, SHA256, ProcessCommandLine=InitiatingProcessCommandLine, InitiatingProcessFileName, InitiatingProcessSHA256, Src="FileLand")
| order by Timestamp desc
```

### [LLM] Kazuar Bridge module: Exchange Web Services C2 from non-mail-client process

`UC_121_7` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_user_agent) as user_agents values(Web.url) as urls from datamodel=Web where (Web.url="*/EWS/Exchange.asmx*" OR Web.url="*/ews/exchange.asmx*") by Web.src Web.user Web.dest Web.app | `drop_dm_object_name(Web)` | where NOT match(app, "(?i)(outlook|msedge|chrome|firefox|msteams|winword|excel|onenote|onedrive|powerpnt|msaccess|mapisvc|iexplore)\.exe") | where NOT match(mvjoin(user_agents,";"), "(?i)(Microsoft Office|MSOffice|Outlook|Mozilla|Chrome|Edge|Firefox|Safari|Teams|ActiveSync|MailClient)") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let MailProcs = dynamic(["outlook.exe","msedge.exe","chrome.exe","firefox.exe","msteams.exe","winword.exe","excel.exe","onenote.exe","onedrive.exe","msaccess.exe","powerpnt.exe","mapisvc.exe","iexplore.exe","opera.exe","brave.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "/EWS/Exchange.asmx" or RemoteUrl has "/ews/exchange.asmx"
| where isnotempty(InitiatingProcessFileName)
| where not(InitiatingProcessFileName has_any (MailProcs))
| where not(InitiatingProcessAccountName endswith "$")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessSHA256, InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Kazuar Worker module: MAPI / Outlook interop DLL load by non-Office process

`UC_121_8` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`sysmon` EventCode=7 (ImageLoaded="*\\mapi32.dll" OR ImageLoaded="*\\olmapi32.dll" OR ImageLoaded="*\\emsmdb32.dll" OR ImageLoaded="*\\msmapi32.dll" OR ImageLoaded="*\\mspst32.dll" OR ImageLoaded="*Microsoft.Office.Interop.Outlook*") NOT (Image IN ("*\\outlook.exe","*\\winword.exe","*\\excel.exe","*\\powerpnt.exe","*\\onenote.exe","*\\onedrive.exe","*\\msaccess.exe","*\\msteams.exe","*\\mapisvc.exe","*\\visio.exe","*\\mspub.exe","*\\communicator.exe","*\\lync.exe","*\\searchindexer.exe")) | stats min(_time) as firstTime max(_time) as lastTime count values(CommandLine) as cmdlines values(Hashes) as hashes by host User Image ImageLoaded | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let OfficeProcs = dynamic(["outlook.exe","winword.exe","excel.exe","powerpnt.exe","onenote.exe","onedrive.exe","msaccess.exe","mspub.exe","visio.exe","mapisvc.exe","msteams.exe","communicator.exe","lync.exe","searchindexer.exe","olk.exe"]);
let MapiDlls = dynamic(["mapi32.dll","mapi.dll","msmapi32.dll","olmapi32.dll","emsmdb32.dll","mspst32.dll","outex.dll","microsoft.office.interop.outlook.dll"]);
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where tolower(FileName) in (MapiDlls) or FileName has "Microsoft.Office.Interop.Outlook"
| where not(tolower(InitiatingProcessFileName) in (OfficeProcs))
| where not(InitiatingProcessFolderPath startswith @"C:\Program Files\Microsoft Office\") and not(InitiatingProcessFolderPath startswith @"C:\Program Files (x86)\Microsoft Office\")
| where not(InitiatingProcessAccountName endswith "$")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessSHA256, LoadedDll=FileName, LoadedDllPath=FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

### [LLM] Kazuar Kernel module: mass encrypted-file staging in working directory

`UC_121_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count dc(Filesystem.file_name) as file_count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_name) as files sum(Filesystem.file_size) as total_bytes from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_path="*\\AppData\\Local\\*" OR Filesystem.file_path="*\\AppData\\Roaming\\*" OR Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\Users\\Public\\*" OR Filesystem.file_path="*\\Windows\\Temp\\*") by Filesystem.dest Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where NOT match(process_name, "(?i)(svchost|msiexec|setup|explorer|onedrive|officeclicktorun|searchindexer|wuauclt|trustedinstaller|msmpeng|mssense|setupapi|compattelrunner|mscorsvw|conhost|taskhostw|msteams|teamsupdate|wermgr|werfault|chrome|msedge|firefox)\.exe") | where file_count >= 20 AND (lastTime - firstTime) <= 1800 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let SystemProcs = dynamic(["svchost.exe","msiexec.exe","setup.exe","explorer.exe","onedrive.exe","onedrivestandaloneupdater.exe","officeclicktorun.exe","searchindexer.exe","wuauclt.exe","trustedinstaller.exe","msmpeng.exe","windefend.exe","mssense.exe","setupapi.exe","compattelrunner.exe","mscorsvw.exe","conhost.exe","taskhostw.exe","msteams.exe","teamsupdate.exe","wermgr.exe","werfault.exe","chrome.exe","msedge.exe","firefox.exe"]);
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType == "FileCreated"
| where FolderPath has_any (@"\AppData\Local\", @"\AppData\Roaming\", @"\ProgramData\", @"\Users\Public\", @"\Windows\Temp\")
| where not(tolower(InitiatingProcessFileName) in (SystemProcs))
| where not(InitiatingProcessAccountName endswith "$")
| extend StageDir = strcat(tostring(split(FolderPath, "\\")[0]), "\\", strcat_array(array_slice(split(FolderPath, "\\"), 1, 5), "\\"))
| summarize FileCount=dcount(FileName), TotalBytes=sum(FileSize), FirstSeen=min(Timestamp), LastSeen=max(Timestamp), SampleFiles=make_set(FileName, 10), Hashes=make_set(SHA256, 5) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessAccountName, StageDir
| where FileCount >= 20 and datetime_diff('minute', LastSeen, FirstSeen) <= 30
| order by FileCount desc
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4`, `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9`, `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d`, `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
