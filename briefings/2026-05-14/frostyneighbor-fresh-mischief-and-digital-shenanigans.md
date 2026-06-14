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
- **T1027.009** — Obfuscated Files or Information: Embedded Payloads
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1583.001** — Acquire Infrastructure: Domains
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1055.001** — Process Injection: DLL Injection
- **T1588.002** — Obtain Capabilities: Tool (Cobalt Strike)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### FrostyNeighbor PicassoLoader drop to %AppData%\WinDataScope\Update.js

`UC_308_12` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as process_name values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_name="Update.js" Filesystem.file_path="*\\AppData\\Roaming\\WinDataScope\\*" by Filesystem.dest Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has @"\AppData\Roaming\WinDataScope" and FileName =~ "Update.js"
| project Timestamp, DeviceName, FolderPath, FileName, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by Timestamp desc
```

### FrostyNeighbor JS dropper self-relaunch with --update flag

`UC_308_13` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") Processes.process="*--update*" Processes.process="*.js*" by Processes.dest Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has "--update"
| where ProcessCommandLine has ".js"
| project Timestamp, DeviceName, AccountName,
          ProcessCommandLine, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### FrostyNeighbor C2 callout to needbinding/nebao/algsat/sardk/alexavegas/lavanille

`UC_308_14` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.app) as app values(All_Traffic.src) as src values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as port from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url="*needbinding.icu*" OR All_Traffic.url="*nebao.icu*" OR All_Traffic.url="*algsat.icu*" OR All_Traffic.url="*alexavegas.icu*" OR All_Traffic.url="*sardk.icu*" OR All_Traffic.url="*lavanille.buzz*") by All_Traffic.user All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let FrostyDomains = dynamic(["needbinding.icu","nebao.icu","algsat.icu","alexavegas.icu","sardk.icu","lavanille.buzz"]);
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(60d)
    | where RemoteUrl has_any (FrostyDomains)
    | extend Source="NetworkEvent"
    | project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, Source;
let EventHits = DeviceEvents
    | where Timestamp > ago(60d)
    | where ActionType =~ "DnsQueryResponse"
    | extend QueriedDomain = tostring(parse_json(AdditionalFields).DnsQueryString)
    | where QueriedDomain has_any (FrostyDomains)
    | extend Source="DnsQuery"
    | project Timestamp, DeviceName, RemoteIP="", RemoteUrl=QueriedDomain,
              RemotePort=tolong(0),
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName=AccountName, Source;
union NetHits, EventHits
| order by Timestamp desc
```

### PicassoLoader scheduled-task creation by wscript/cscript after C2 XML fetch

`UC_308_15` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("wscript.exe","cscript.exe") (Processes.process_name="schtasks.exe" OR (Processes.process_name="powershell.exe" AND Processes.process="*Register-ScheduledTask*") OR Processes.process_name="taskeng.exe") (Processes.process="*/Create*" OR Processes.process="*Register-ScheduledTask*" OR Processes.process="*/XML*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where (FileName =~ "schtasks.exe" and ProcessCommandLine has_any ("/Create","/XML"))
      or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Register-ScheduledTask")
| project Timestamp, DeviceName, AccountName,
          ChildProcess=FileName, ChildCmd=ProcessCommandLine,
          ParentProcess=InitiatingProcessFileName,
          ParentCmd=InitiatingProcessCommandLine,
          GrandparentProcess=InitiatingProcessParentFileName,
          SHA256
| order by Timestamp desc
```

### FrostyNeighbor Cobalt Strike beacon ViberPC.dll image load

`UC_308_16` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.dest) as host values(Filesystem.user) as user values(Filesystem.process_name) as process from datamodel=Endpoint.Filesystem where Filesystem.file_name="ViberPC.dll" (Filesystem.file_hash="43E30BE82D82B24A6496F6943ECB6877E83F88AB" OR NOT Filesystem.file_path IN ("*\\Viber\\*","*\\Program Files*\\Viber*")) by Filesystem.file_path Filesystem.file_hash | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let FrostyHashes = dynamic(["43E30BE82D82B24A6496F6943ECB6877E83F88AB"]);
let ImageLoads = DeviceImageLoadEvents
    | where Timestamp > ago(60d)
    | where FileName =~ "ViberPC.dll"
    | where SHA1 in~ (FrostyHashes)
         or not (FolderPath has @"\Viber\" or FolderPath has @"\Program Files\Viber")
    | project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, Source="ImageLoad";
let FileWrites = DeviceFileEvents
    | where Timestamp > ago(60d)
    | where FileName =~ "ViberPC.dll"
    | where SHA1 in~ (FrostyHashes)
         or not (FolderPath has @"\Viber\" or FolderPath has @"\Program Files\Viber")
    | project Timestamp, DeviceName, FileName, FolderPath, SHA1, SHA256,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, Source="FileWrite";
union ImageLoads, FileWrites
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

`UC_308_11` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: CVE present, IOCs present, 17 use case(s) fired, 25 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
