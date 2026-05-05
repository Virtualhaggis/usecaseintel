# [CRIT] Gamaredon X Turla collab

**Source:** ESET WeLiveSecurity
**Published:** 2025-09-19
**Article:** https://www.welivesecurity.com/en/eset-research/gamaredon-x-turla-collab/

## Threat Profile

Gamaredon X Turla collab 
ESET Research
Gamaredon X Turla collab Notorious APT group Turla collaborates with Gamaredon, both FSB-associated groups, to compromise high‑profile targets in Ukraine
Matthieu Faou 
Zoltán Rusnák 
19 Sep 2025 
 •  
, 
16 min. read 
In this blogpost, we uncover the first known cases of collaboration between Gamaredon and Turla, in Ukraine.
Key points of this blogpost: 
In February 2025, we discovered that the Gamaredon tool PteroGraphin was used to restart Turla’s Kazua…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `91.231.182.187`
- **IPv4 (defanged):** `64.176.173.164`
- **IPv4 (defanged):** `85.13.145.231`
- **IPv4 (defanged):** `185.118.115.15`
- **IPv4 (defanged):** `77.46.148.242`
- **IPv4 (defanged):** `168.119.152.19`
- **IPv4 (defanged):** `217.160.0.33`
- **IPv4 (defanged):** `217.160.0.159`
- **Domain (defanged):** `api.telegra.ph`
- **Domain (defanged):** `lucky-king-96d6.mopig92456.workers.dev`
- **Domain (defanged):** `eset.ydns.eu`
- **Domain (defanged):** `api.gofile.io`
- **Domain (defanged):** `abrargeospatial.ir`
- **Domain (defanged):** `www.brannenburger-nagelfluh.de`
- **Domain (defanged):** `www.pizzeria-mercy.de`
- **Domain (defanged):** `ekrn.ydns.eu`
- **Domain (defanged):** `ig92456.workers.dev`
- **Domain (defanged):** `albenstrasse.de`
- **Domain (defanged):** `fjsconsultoria.com`
- **Domain (defanged):** `ingas.rs`
- **Domain (defanged):** `er-nagelfluh.de`

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
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1132.001** — Data Encoding: Standard Encoding
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1036.005** — Masquerading: Match Legitimate Resource Name or Location
- **T1041** — Exfiltration Over C2 Channel
- **T1102** — Web Service
- **T1568** — Dynamic Resolution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Gamaredon PteroGraphin/PteroOdd C2 — PowerShell GET to api.telegra.ph/getPage

`UC_339_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_name IN ("powershell.exe","pwsh.exe") AND (Processes.process="*api.telegra.ph/getPage*" OR Processes.process="*telegra.ph*getPage*return_content=true*" OR Processes.process="*SecurityHealthSystray-*" OR Processes.process="*dinoasjdnl-*" OR Processes.process="*canposgam-*") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count from datamodel=Web.Web where Web.url="*api.telegra.ph/getPage*" AND Web.url="*return_content=true*" by Web.src Web.user Web.url Web.app | `drop_dm_object_name(Web)`]
```

**Defender KQL:**
```kql
let lookback = 7d;
let TelegraphPS = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where InitiatingProcessAccountName !endswith "$"
    | where FileName in~ ("powershell.exe","pwsh.exe")
    | where ProcessCommandLine has "telegra.ph"
    | where ProcessCommandLine has "getPage"
          or ProcessCommandLine has "return_content=true"
          or ProcessCommandLine has_any ("SecurityHealthSystray-","dinoasjdnl-","canposgam-")
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256;
let TelegraphNet = DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where RemoteUrl has "api.telegra.ph" and RemoteUrl has "getPage"
    | where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe")
    | project Timestamp, DeviceName, RemoteUrl, RemoteIP,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName;
union TelegraphPS, TelegraphNet
| order by Timestamp desc
```

### [LLM] Turla Kazuar v3 launch — vncutil64.exe / LaunchGFExperience.exe side-load from user-writable path

`UC_339_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as process_path values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="vncutil64.exe" OR Processes.process_name="LaunchGFExperience.exe") AND (Processes.process_path="*\\AppData\\Local\\Programs\\Sony\\Audio\\Drivers\\*" OR Processes.process_path="*\\AppData\\*" OR Processes.process_path="*\\Users\\Public\\*" OR Processes.process_path="*\\Temp\\*" OR Processes.process_path="*\\ProgramData\\*") by host Processes.user Processes.process_name Processes.process_path Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where Filesystem.file_name="LaunchGFExperienceLOC.dll" by host Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let lookback = 14d;
let KazuarShells = dynamic(["vncutil64.exe","LaunchGFExperience.exe"]);
let ProcHits = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ (KazuarShells)
    | where FolderPath has_any (@"\AppData\Local\Programs\Sony\Audio\Drivers\",
                                 @"\AppData\Local\",
                                 @"\AppData\Roaming\",
                                 @"\Users\Public\",
                                 @"\ProgramData\",
                                 @"\Windows\Temp\")
    | project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256,
              ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let DllSideLoad = DeviceImageLoadEvents
    | where Timestamp > ago(lookback)
    | where FileName =~ "LaunchGFExperienceLOC.dll"
          or (FileName =~ "LaunchGFExperience.exe" and FolderPath !startswith @"C:\Program Files\NVIDIA Corporation\")
    | project Timestamp, DeviceName, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessFolderPath,
              InitiatingProcessCommandLine, InitiatingProcessSHA256;
let DllDrop = DeviceFileEvents
    | where Timestamp > ago(lookback)
    | where FileName =~ "LaunchGFExperienceLOC.dll" or FileName =~ "vncutil64.exe"
    | where FolderPath !startswith @"C:\Program Files\" and FolderPath !startswith @"C:\Program Files (x86)\"
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256,
              InitiatingProcessFileName, InitiatingProcessAccountName, InitiatingProcessCommandLine;
union ProcHits, DllSideLoad, DllDrop
| order by Timestamp desc
```

### [LLM] Turla Kazuar exfil — POST to ESET-impersonating ydns.eu lookalikes / mopig92456 Cloudflare worker

`UC_339_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution.DNS where DNS.query IN ("eset.ydns.eu","ekrn.ydns.eu","lucky-king-96d6.mopig92456.workers.dev") OR DNS.query="*.mopig92456.workers.dev" by DNS.query | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats `summariesonly` count from datamodel=Web.Web where (Web.url="*eset.ydns.eu/post.php*" OR Web.url="*ekrn.ydns.eu*" OR Web.url="*mopig92456.workers.dev*") by Web.src Web.user Web.url Web.http_method Web.app | `drop_dm_object_name(Web)`] | append [| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("91.231.182.187","64.176.173.164","85.13.145.231","185.118.115.15","77.46.148.242","168.119.152.19","217.160.0.33","217.160.0.159")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
let lookback = 30d;
let TurlaC2Domains = dynamic(["eset.ydns.eu","ekrn.ydns.eu","lucky-king-96d6.mopig92456.workers.dev"]);
let TurlaC2IPs = dynamic(["91.231.182.187","64.176.173.164","85.13.145.231","185.118.115.15","77.46.148.242","168.119.152.19","217.160.0.33","217.160.0.159"]);
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(lookback)
    | where (RemoteUrl in~ (TurlaC2Domains))
          or (RemoteUrl endswith ".mopig92456.workers.dev")
          or (RemoteUrl has "eset.ydns.eu" and RemoteUrl has "post.php")
          or (RemoteIP in (TurlaC2IPs))
    | project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessAccountName, InitiatingProcessFolderPath;
let DnsHits = DeviceEvents
    | where Timestamp > ago(lookback)
    | where ActionType == "DnsQueryResponse"
    | extend Q = tolower(tostring(parse_json(AdditionalFields).QueryName))
    | where Q in (TurlaC2Domains) or Q endswith ".mopig92456.workers.dev"
    | project Timestamp, DeviceName, Q, InitiatingProcessFileName, InitiatingProcessCommandLine;
union NetHits, DnsHits
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

### Article-specific behavioural hunt — Gamaredon X Turla collab

`UC_339_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Gamaredon X Turla collab ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("x86.ps1","vncutil64.exe","launchgfexperience.exe","launchgfexperienceloc.dll","scrss.ps1","ekrn.ps1","ekrn.exe","sandboxie.vbs") OR Processes.process="*-EncodedCommand*" OR Processes.process="*DownloadString*" OR Processes.process="*IEX(*" OR Processes.process="*Net.WebClient*" OR Processes.process="*-WindowStyle Hidden*" OR Processes.process_path="*\AppData\Local\Programs\Sony\Audio\Drivers\vncutil64.exe*" OR Processes.process_path="*%APPDATA%\Microsoft\Windows*" OR Processes.process_path="*%LOCALAPPDATA%\Programs\Sony\Audio\*")
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*\AppData\Local\Programs\Sony\Audio\Drivers\vncutil64.exe*" OR Filesystem.file_path="*%APPDATA%\Microsoft\Windows*" OR Filesystem.file_path="*%LOCALAPPDATA%\Programs\Sony\Audio\*" OR Filesystem.file_name IN ("x86.ps1","vncutil64.exe","launchgfexperience.exe","launchgfexperienceloc.dll","scrss.ps1","ekrn.ps1","ekrn.exe","sandboxie.vbs"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
| append [
  | tstats `summariesonly` count
      from datamodel=Endpoint.Registry
      where Registry.action IN ("created","modified")
        AND (Registry.registry_path="*HKLM\\SOFTWARE\\Microsoft\\NET*")
      by Registry.dest, Registry.process_name, Registry.registry_path,
         Registry.registry_value_name, Registry.registry_value_data
  | `drop_dm_object_name(Registry)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Gamaredon X Turla collab
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("x86.ps1", "vncutil64.exe", "launchgfexperience.exe", "launchgfexperienceloc.dll", "scrss.ps1", "ekrn.ps1", "ekrn.exe", "sandboxie.vbs") or ProcessCommandLine has_any ("-EncodedCommand", "DownloadString", "IEX(", "Net.WebClient", "-WindowStyle Hidden") or FolderPath has_any ("\AppData\Local\Programs\Sony\Audio\Drivers\vncutil64.exe", "%APPDATA%\Microsoft\Windows", "%LOCALAPPDATA%\Programs\Sony\Audio\"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("\AppData\Local\Programs\Sony\Audio\Drivers\vncutil64.exe", "%APPDATA%\Microsoft\Windows", "%LOCALAPPDATA%\Programs\Sony\Audio\") or FileName in~ ("x86.ps1", "vncutil64.exe", "launchgfexperience.exe", "launchgfexperienceloc.dll", "scrss.ps1", "ekrn.ps1", "ekrn.exe", "sandboxie.vbs"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc

// Registry persistence locations named in the article
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryKey has_any ("HKLM\SOFTWARE\Microsoft\NET")
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `91.231.182.187`, `64.176.173.164`, `85.13.145.231`, `185.118.115.15`, `77.46.148.242`, `168.119.152.19`, `217.160.0.33`, `217.160.0.159` _(+13 more)_


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
