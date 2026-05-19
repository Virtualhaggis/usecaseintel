# [CRIT] FrostyNeighbor: Fresh mischief and digital shenanigans

**Source:** ESET WeLiveSecurity
**Published:** 2026-05-14
**Article:** https://www.welivesecurity.com/en/eset-research/frostyneighbor-fresh-mischief-digital-shenanigans/

## Threat Profile

FrostyNeighbor: Fresh mischief and digital shenanigans 
ESET Research
FrostyNeighbor: Fresh mischief and digital shenanigans ESET researchers uncovered new activities attributed to FrostyNeighbor, updating its compromise chain to support the group’s continual cyberespionage operations
Damien Schaeffer 
14 May 2026 
 •  
, 
10 min. read 
This blogpost covers newly discovered activities attributed to FrostyNeighbor, targeting governmental organizations in Ukraine. FrostyNeighbor has been running c…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-38831`
- **CVE:** `CVE-2024-42009`
- **Domain (defanged):** `book-happy.needbinding.icu`
- **Domain (defanged):** `nama-belakang.nebao.icu`
- **Domain (defanged):** `needbinding.icu`
- **Domain (defanged):** `nebao.icu`
- **SHA1:** `776A43E46C36A539C916ED426745EE96E2392B39`
- **SHA1:** `8D1F2A6DF51C7783F2EAF1A0FC0FF8D032E5B57F`
- **SHA1:** `B65551D339AECE718EA1465BF3542C794C445EFC`
- **SHA1:** `43E30BE82D82B24A6496F6943ECB6877E83F88AB`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1190** — Exploit Public-Facing Application
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
- **T1195.002** — Compromise Software Supply Chain
- **T1053.005** — Persistence (article-specific)
- **T1547.001** — Persistence (article-specific)
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1036.003** — Masquerading: Rename System Utilities
- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1564.001** — Hide Artifacts: Hidden Files and Directories
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1102** — Web Service
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1112** — Modify Registry
- **T1059** — Command and Scripting Interpreter
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1027.009** — Obfuscated Files or Information: Embedded Payloads

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] FrostyNeighbor PicassoLoader drop at %AppData%\WinDataScope\Update.js

`UC_81_12` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\AppData\\Roaming\\WinDataScope\\Update.js" OR Filesystem.file_path="*\\AppData\\Roaming\\WinDataScope\\WinUpdate.reg" OR Filesystem.file_path="*\\AppData\\Roaming\\WinDataScope\\*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\WinDataScope\"
   or FileName in~ ("Update.js","WinUpdate.reg")
   and FolderPath has @"\AppData\Roaming\"
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe","explorer.exe","winrar.exe","7zg.exe","7zfm.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA1, SHA256
| order by Timestamp desc
```

### [LLM] FrostyNeighbor rundll32.exe masquerade copy as %ProgramData%\ViberPC.exe

`UC_81_13` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\ProgramData\\ViberPC.exe" OR Filesystem.file_path="*\\ProgramData\\ViberPC.dll" OR Filesystem.file_path="*\\ProgramData\\ViberPC.lnk" OR Filesystem.file_path="*\\ProgramData\\ViberPC.reg" OR Filesystem.file_path="*\\ProgramData\\EdgeSystemConfig.dll") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has @"\ProgramData\"
| where FileName in~ ("ViberPC.exe","ViberPC.dll","ViberPC.lnk","ViberPC.reg","EdgeSystemConfig.dll")
| where InitiatingProcessFileName !in~ ("msiexec.exe","trustedinstaller.exe")
| extend RenamedRundll32 = iff(FileName =~ "ViberPC.exe", true, false)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA1, SHA256, RenamedRundll32
| order by Timestamp desc
```

### [LLM] FrostyNeighbor C2 contact to needbinding.icu / nebao.icu / sardk.icu domains

`UC_81_14` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count values(Web.url) as urls min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*needbinding.icu*" OR Web.url="*nebao.icu*" OR Web.url="*algsat.icu*" OR Web.url="*alexavegas.icu*" OR Web.url="*sardk.icu*" OR Web.url="*lavanille.buzz*" OR Web.url="*/employment/documents-and-resources*" OR Web.url="*/statistics/discover.txt*" OR Web.url="*1GreenAM.jpg*") by Web.src Web.dest Web.http_user_agent Web.http_method | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let FrostyDomains = dynamic(["needbinding.icu","nebao.icu","algsat.icu","alexavegas.icu","sardk.icu","lavanille.buzz"]);
let FrostyUriPaths = dynamic(["/employment/documents-and-resources","/statistics/discover.txt","/wp-content/uploads/2023/10/1GreenAM.jpg"]);
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where (RemoteUrl has_any (FrostyDomains)
         or RemoteUrl has_any (FrostyUriPaths))
    | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, ActionType;
let DnsHits = DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
    | where QueryName has_any (FrostyDomains)
    | project Timestamp, DeviceName, InitiatingProcessFileName, QueryName, RemoteIP="", RemoteUrl=QueryName, RemotePort=int(53), ActionType="DnsQueryResponse", InitiatingProcessCommandLine;
union NetHits, DnsHits
| order by Timestamp desc
```

### [LLM] FrostyNeighbor HKCU Run persistence pointing to %ProgramData%\ViberPC.lnk

`UC_81_15` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where (Registry.registry_path="*\\CurrentVersion\\Run*" OR Registry.registry_path="*\\CurrentVersion\\RunOnce*") AND (Registry.registry_value_data="*ViberPC.lnk*" OR Registry.registry_value_data="*\\ProgramData\\ViberPC*" OR Registry.registry_value_data="*EdgeSystemConfig*") by Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.registry_value_data Registry.process_name | `drop_dm_object_name(Registry)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce")
| where RegistryValueData has_any ("ViberPC.lnk","ViberPC.exe",@"\ProgramData\ViberPC","EdgeSystemConfig")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### [LLM] FrostyNeighbor renamed-rundll32 invoking ViberPC.dll export SettingTimeAPI

`UC_81_16` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*ViberPC.dll*SettingTimeAPI*" OR Processes.process="*EdgeSystemConfig.dll*" OR (Processes.process_path="*\\ProgramData\\ViberPC.exe" AND Processes.process="*.dll*")) by Processes.dest Processes.user Processes.process_name Processes.process_path Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "SettingTimeAPI" and ProcessCommandLine has "ViberPC.dll")
    or (FolderPath =~ @"C:\ProgramData\" and FileName =~ "ViberPC.exe")
    or (ProcessCommandLine has @"\ProgramData\ViberPC.dll")
    or (ProcessCommandLine has "EdgeSystemConfig.dll")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA1, SHA256
| order by Timestamp desc
```

### [LLM] FrostyNeighbor SHA-1 IOC sweep (PicassoLoader / Cobalt Strike beacon / lure files)

`UC_81_17` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("776A43E46C36A539C916ED426745EE96E2392B39","8D1F2A6DF51C7783F2EAF1A0FC0FF8D032E5B57F","B65551D339AECE718EA1465BF3542C794C445EFC","E15ABEE1CFDE8BE7D87C7C0B510450BAD6BC0906","43E30BE82D82B24A6496F6943ECB6877E83F88AB","4F2C1856325372B9B7769D00141DBC1A23BDDD14","D89E5524E49199B1C3B66C524E7A63C3F0A0C199","7E537D8E91668580A482BD77A5A4CABA26D6BDAC","FA6882672AD3654800987613310D7C3FBADE027E","3FA7D1B13542F1A9EB054111F9B69C250AF68643","4E52C92709A918383E90534052AAA257ACE2780C","6FDED427A16D5314BA3E1EB9AFD120DC84449769","27FA11F6A1D653779974B6FB54DE4AF47F211232") by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let FrostySha1 = dynamic([
    "776A43E46C36A539C916ED426745EE96E2392B39",
    "8D1F2A6DF51C7783F2EAF1A0FC0FF8D032E5B57F",
    "B65551D339AECE718EA1465BF3542C794C445EFC",
    "E15ABEE1CFDE8BE7D87C7C0B510450BAD6BC0906",
    "43E30BE82D82B24A6496F6943ECB6877E83F88AB",
    "4F2C1856325372B9B7769D00141DBC1A23BDDD14",
    "D89E5524E49199B1C3B66C524E7A63C3F0A0C199",
    "7E537D8E91668580A482BD77A5A4CABA26D6BDAC",
    "FA6882672AD3654800987613310D7C3FBADE027E",
    "3FA7D1B13542F1A9EB054111F9B69C250AF68643",
    "4E52C92709A918383E90534052AAA257ACE2780C",
    "6FDED427A16D5314BA3E1EB9AFD120DC84449769",
    "27FA11F6A1D653779974B6FB54DE4AF47F211232"]);
let FileHits = DeviceFileEvents
    | where Timestamp > ago(60d)
    | where SHA1 in~ (FrostySha1)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, Source="DeviceFileEvents";
let ProcHits = DeviceProcessEvents
    | where Timestamp > ago(60d)
    | where SHA1 in~ (FrostySha1) or InitiatingProcessSHA1 in~ (FrostySha1)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName=tostring(InitiatingProcessFileName), Source="DeviceProcessEvents";
let ImgHits = DeviceImageLoadEvents
    | where Timestamp > ago(60d)
    | where SHA1 in~ (FrostySha1)
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, SHA256, InitiatingProcessFileName, Source="DeviceImageLoadEvents";
union FileHits, ProcHits, ImgHits
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

### Article-specific behavioural hunt — FrostyNeighbor: Fresh mischief and digital shenanigans

`UC_81_11` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — FrostyNeighbor: Fresh mischief and digital shenanigans ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("53_7.03.2026_r.js","update.js","viberpc.exe","viberpc.dll","certificate.js") OR Processes.process_path="*%AppData%\WinDataScope\Update.js*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*%AppData%\WinDataScope\Update.js*" OR Filesystem.file_name IN ("53_7.03.2026_r.js","update.js","viberpc.exe","viberpc.dll","certificate.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — FrostyNeighbor: Fresh mischief and digital shenanigans
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("53_7.03.2026_r.js", "update.js", "viberpc.exe", "viberpc.dll", "certificate.js") or FolderPath has_any ("%AppData%\WinDataScope\Update.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("%AppData%\WinDataScope\Update.js") or FileName in~ ("53_7.03.2026_r.js", "update.js", "viberpc.exe", "viberpc.dll", "certificate.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `book-happy.needbinding.icu`, `nama-belakang.nebao.icu`, `needbinding.icu`, `nebao.icu`

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-38831`, `CVE-2024-42009`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `776A43E46C36A539C916ED426745EE96E2392B39`, `8D1F2A6DF51C7783F2EAF1A0FC0FF8D032E5B57F`, `B65551D339AECE718EA1465BF3542C794C445EFC`, `43E30BE82D82B24A6496F6943ECB6877E83F88AB`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 18 use case(s) fired, 31 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
