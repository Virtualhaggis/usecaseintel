# [CRIT] Sednit reloaded: Back in the trenches

**Source:** ESET WeLiveSecurity
**Published:** 2026-03-10
**Article:** https://www.welivesecurity.com/en/eset-research/sednit-reloaded-back-trenches/

## Threat Profile

Sednit reloaded: Back in the trenches 
ESET Research
Sednit reloaded: Back in the trenches The resurgence of one of Russia’s most notorious APT groups
ESET Research 
10 Mar 2026 
 •  
, 
13 min. read 
Since April 2024, Sednit’s advanced development team has reemerged with a modern toolkit centered on two paired implants, BeardShell and Covenant, each using a different cloud provider for resilience. This dual‑implant approach enabled long‑term surveillance of Ukrainian military personnel. Interes…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-21509`
- **SHA1:** `D0DB619A7A160949528D46D20FC0151BF9775C32`
- **SHA1:** `99B454262DC26B081600E844371982A49D334E5E`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1190** — Exploit Public-Facing Application
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1566.001** — Spearphishing Attachment
- **T1204.002** — User Execution: Malicious File
- **T1059.005** — Visual Basic
- **T1218** — System Binary Proxy Execution
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1102.002** — Web Service: Bidirectional Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1568** — Dynamic Resolution
- **T1056.001** — Input Capture: Keylogging
- **T1115** — Clipboard Data
- **T1113** — Screen Capture

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Sednit BeardShell C2 over Icedrive cloud storage from non-browser process

`UC_177_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.app) as app values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="*.icedrive.net" OR All_Traffic.dest_host="icedrive.net" OR All_Traffic.dest_host="*.icedrive.com") by All_Traffic.src All_Traffic.dest_host host All_Traffic.process_name
| `drop_dm_object_name("All_Traffic")`
| where NOT match(process_name, "(?i)(chrome|msedge|firefox|iexplore|brave|opera|safari|icedrive)\\.exe$")
| join type=outer host [| tstats `summariesonly` values(Processes.process) as process values(Processes.process_name) as proc_name from datamodel=Endpoint.Processes where (Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="dotnet.exe" OR Processes.process_name="InstallUtil.exe" OR Processes.parent_process_name="w3wp.exe") by host | `drop_dm_object_name("Processes")`]
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let icedriveDomains = dynamic(["icedrive.net","icedrive.com","api.icedrive.net"]);
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe","opera.exe","safari.exe","Icedrive.exe","icedrive.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (icedriveDomains) or tostring(parse_url(RemoteUrl).Host) has_any (icedriveDomains)
| where InitiatingProcessFileName !in~ (browsers)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("powershell.exe","pwsh.exe","dotnet.exe","InstallUtil.exe","RegAsm.exe","RegSvcs.exe")
    | project DeviceName, ProcContext=ProcessCommandLine, ProcTime=Timestamp
) on DeviceName
| where ProcTime between (Timestamp - 1h .. Timestamp + 1h) or isempty(ProcContext)
| summarize hits=count(), firstSeen=min(Timestamp), lastSeen=max(Timestamp), processes=make_set(InitiatingProcessFileName, 16), urls=make_set(RemoteUrl, 16) by DeviceName
```

### [LLM] Sednit modified-Covenant C2 over Filen / pCloud / Koofr cloud storage

`UC_177_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.bytes_out) as bytes_out from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_host="*.filen.io" OR All_Traffic.dest_host="*.filen.net" OR All_Traffic.dest_host="*.pcloud.com" OR All_Traffic.dest_host="api.pcloud.com" OR All_Traffic.dest_host="*.koofr.net" OR All_Traffic.dest_host="app.koofr.net") by All_Traffic.src host All_Traffic.dest_host All_Traffic.process_name All_Traffic.user
| `drop_dm_object_name("All_Traffic")`
| where NOT match(process_name, "(?i)(chrome|msedge|firefox|iexplore|brave|opera|safari|filen|pcloud|koofr)\\.exe$")
| eval beacon_minutes=round((lastTime-firstTime)/60,0)
| where beacon_minutes>30 OR count>20
| join type=outer host [| tstats `summariesonly` values(Processes.process_name) as parent_proc values(Processes.process) as proc_cmd from datamodel=Endpoint.Processes where (Processes.process_name IN ("dotnet.exe","powershell.exe","pwsh.exe","InstallUtil.exe","RegAsm.exe","RegSvcs.exe","MSBuild.exe")) by host | `drop_dm_object_name("Processes")`]
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let covenantC2 = dynamic(["filen.io","api.filen.io","gateway.filen.io","egest.filen.io","ingest.filen.io","filen.net","pcloud.com","api.pcloud.com","eapi.pcloud.com","koofr.net","app.koofr.net","api.koofr.net"]);
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe","brave.exe","opera.exe","safari.exe","Filen.exe","pCloud.exe","koofr.exe"]);
let netHits = DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | extend hostName = tostring(parse_url(RemoteUrl).Host)
    | where RemoteUrl has_any (covenantC2) or hostName has_any (covenantC2)
    | where InitiatingProcessFileName !in~ (browsers)
    | summarize firstSeen=min(Timestamp), lastSeen=max(Timestamp), conns=count(), urls=make_set(RemoteUrl,16) by DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256
    | extend durationMin = datetime_diff('minute', lastSeen, firstSeen)
    | where durationMin > 30 or conns > 20;
netHits
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("dotnet.exe","powershell.exe","pwsh.exe","InstallUtil.exe","RegAsm.exe","RegSvcs.exe","MSBuild.exe")
    | summarize dotnetProcs=make_set(ProcessCommandLine, 8) by DeviceName
) on DeviceName
| project DeviceName, InitiatingProcessFileName, InitiatingProcessSHA256, conns, durationMin, firstSeen, lastSeen, urls, dotnetProcs
```

### [LLM] SlimAgent keylogger HTML log artefacts (Xagent-derived color scheme)

`UC_177_11` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path from datamodel=Endpoint.Filesystem where (Filesystem.file_name="*.html" OR Filesystem.file_name="*.htm" OR Filesystem.file_name="*.log" OR Filesystem.file_name="*.dat") AND (Filesystem.file_path="*\\AppData\\*" OR Filesystem.file_path="*\\ProgramData\\*" OR Filesystem.file_path="*\\Temp\\*" OR Filesystem.file_path="*\\Public\\*") by host Filesystem.process_name Filesystem.user Filesystem.file_name Filesystem.file_path
| `drop_dm_object_name("Filesystem")`
| where NOT match(process_name, "(?i)(chrome|msedge|firefox|outlook|winword|excel|onenote)\\.exe$")
| join type=inner host file_name [search index=* sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 (TargetFilename="*.html" OR TargetFilename="*.log")
  | rex field=_raw "(?i)(?<color_blue><font[^>]*color=[\"']?(?:blue|#0000ff)[\"']?[^>]*>)"
  | rex field=_raw "(?i)(?<color_red><font[^>]*color=[\"']?(?:red|#ff0000)[\"']?[^>]*>)"
  | rex field=_raw "(?i)(?<color_green><font[^>]*color=[\"']?(?:green|#00ff00|#008000)[\"']?[^>]*>)"
  | where isnotnull(color_blue) AND isnotnull(color_red) AND isnotnull(color_green)
  | rename TargetFilename as file_path, ComputerName as host | fields host file_path]
| `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let suspectPaths = dynamic([@"\AppData\",@"\ProgramData\",@"\Temp\",@"\Public\",@"\Windows\Tasks\"]);
let browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","iexplore.exe","outlook.exe","winword.exe","excel.exe","onenote.exe"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where FileName endswith ".html" or FileName endswith ".htm" or FileName endswith ".log" or FileName endswith ".dat"
| where FolderPath has_any (suspectPaths)
| where InitiatingProcessFileName !in~ (browsers)
| where InitiatingProcessFolderPath !startswith @"C:\Program Files"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any ("GetForegroundWindow","SetWindowsHookEx","<font color=\"blue\"","<font color=\"red\"","<font color=\"green\"")
    | project DeviceName, ProcCmd=ProcessCommandLine, ProcTime=Timestamp
) on DeviceName
| where ProcTime between (Timestamp - 24h .. Timestamp + 24h)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FolderPath, FileName, SHA256, ProcCmd
| summarize files=make_set(strcat(FolderPath,FileName), 16), procs=make_set(InitiatingProcessFileName, 8) by DeviceName, bin(Timestamp, 1d)
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
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### Article-specific behavioural hunt — Sednit reloaded: Back in the trenches

`UC_177_8` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Sednit reloaded: Back in the trenches ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("remotekeylogger.dll","eapphost.dll","tcpiphlpsvc.dll","taskhost.exe"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("remotekeylogger.dll","eapphost.dll","tcpiphlpsvc.dll","taskhost.exe"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Sednit reloaded: Back in the trenches
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("remotekeylogger.dll", "eapphost.dll", "tcpiphlpsvc.dll", "taskhost.exe"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("remotekeylogger.dll", "eapphost.dll", "tcpiphlpsvc.dll", "taskhost.exe"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-21509`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `D0DB619A7A160949528D46D20FC0151BF9775C32`, `99B454262DC26B081600E844371982A49D334E5E`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 12 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
