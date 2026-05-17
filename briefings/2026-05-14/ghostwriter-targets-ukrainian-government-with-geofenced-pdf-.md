# [CRIT] Ghostwriter Targets Ukrainian Government With Geofenced PDF Phishing, Cobalt Strike

**Source:** The Hacker News
**Published:** 2026-05-14
**Article:** https://thehackernews.com/2026/05/ghostwriter-targets-ukrainian.html

## Threat Profile

Ghostwriter Targets Ukrainian Government With Geofenced PDF Phishing, Cobalt Strike 
 Ravie Lakshmanan  May 14, 2026 Hacktivism / Data Theft 
The Belarus-aligned threat group known as Ghostwriter has been attributed to a fresh set of attacks targeting governmental organizations in Ukraine.
Active since at least 2016, Ghostwriter has been linked to both cyber espionage and influence operations targeting neighboring countries, particularly Ukraine. It's also tracked under the monikers FrostyNeig…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2023-38831`
- **CVE:** `CVE-2024-42009`
- **CVE:** `CVE-2025-8088`

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
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1029** — Scheduled Transfer
- **T1082** — System Information Discovery
- **T1203** — Exploitation for Client Execution
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1053.005** — Scheduled Task/Job: Scheduled Task

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Ghostwriter PDF→RAR→JS chain: wscript spawned by archiver executing .js from user-download paths

`UC_59_7` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="WinRAR.exe" OR Processes.parent_process_name="winrar.exe" OR Processes.parent_process_name="Rar.exe" OR Processes.parent_process_name="7zFM.exe" OR Processes.parent_process_name="7zG.exe" OR Processes.parent_process_name="7z.exe" OR Processes.parent_process_name="UnRAR.exe") (Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") (Processes.process="*.js*" OR Processes.process="*.jse*" OR Processes.process="*.vbs*" OR Processes.process="*.wsf*") (Processes.process="*\\Downloads\\*" OR Processes.process="*\\Temp\\*" OR Processes.process="*\\AppData\\Local\\Temp\\*" OR Processes.parent_process="*\\Downloads\\*" OR Processes.parent_process="*\\Temp\\*") by host Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash
| `drop_dm_object_name(Processes)`
| where user!="SYSTEM" AND NOT match(user,"\\$$")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("winrar.exe","7zfm.exe","7zg.exe","7z.exe","rar.exe","unrar.exe","bandizip.exe","peazip.exe")
| where FileName in~ ("wscript.exe","cscript.exe","mshta.exe")
| where ProcessCommandLine has_any (".js",".jse",".vbs",".wsf",".hta")
| where ProcessCommandLine has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\", @"\Public\")
   or InitiatingProcessFolderPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentPath = InitiatingProcessFolderPath,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] PicassoLoader 10-minute HTTP POST fingerprint beacon from wscript/cscript

`UC_59_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app="wscript.exe" OR All_Traffic.app="cscript.exe" OR All_Traffic.process_name="wscript.exe" OR All_Traffic.process_name="cscript.exe") All_Traffic.dest_category!="internal" (All_Traffic.dest_port=80 OR All_Traffic.dest_port=443 OR All_Traffic.dest_port=8080 OR All_Traffic.dest_port=8443) by _time span=1s All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| sort 0 src dest app _time
| streamstats current=f window=1 last(_time) as prev_time by src dest app
| eval interval = _time - prev_time
| where interval>=480 AND interval<=720
| stats count as beacon_count avg(interval) as avg_interval_sec stdev(interval) as stdev_interval_sec min(_time) as first_seen max(_time) as last_seen values(dest_port) as ports by src user dest app
| where beacon_count>=3 AND stdev_interval_sec<60
| convert ctime(first_seen) ctime(last_seen)
| sort - beacon_count
```

**Defender KQL:**
```kql
let lookback = 2d;
let minInterval = 480;  // 8 minutes
let maxInterval = 720;  // 12 minutes
DeviceNetworkEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceId, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessId, RemoteIP, RemoteUrl, RemotePort
| extend BeaconKey = strcat(DeviceId, "|", RemoteIP, "|", tostring(InitiatingProcessId))
| sort by BeaconKey asc, Timestamp asc
| extend PrevTime = prev(Timestamp), PrevKey = prev(BeaconKey)
| where BeaconKey == PrevKey
| extend IntervalSec = datetime_diff('second', Timestamp, PrevTime)
| where IntervalSec between (minInterval .. maxInterval)
| summarize BeaconCount = count(),
            AvgIntervalSec = avg(IntervalSec),
            StdevIntervalSec = stdev(IntervalSec),
            FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            SampleUrl = any(RemoteUrl),
            SampleCmd = any(InitiatingProcessCommandLine)
            by DeviceName, AccountName = InitiatingProcessAccountName, RemoteIP, InitiatingProcessFileName
| where BeaconCount >= 3 and StdevIntervalSec < 60   // tight ~10-min cadence
| order by BeaconCount desc
```

### [LLM] CVE-2025-8088 WinRAR ADS path-traversal writes to Startup or Tasks folder

`UC_59_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.process_name="WinRAR.exe" OR Filesystem.process_name="winrar.exe" OR Filesystem.process_name="Rar.exe" OR Filesystem.process_name="UnRAR.exe" OR Filesystem.process_name="7zFM.exe" OR Filesystem.process_name="7zG.exe" OR Filesystem.process_name="7z.exe" OR Filesystem.process_name="Bandizip.exe") (Filesystem.file_path="*\\Start Menu\\Programs\\Startup\\*" OR Filesystem.file_path="*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*" OR Filesystem.file_path="*\\System32\\Tasks\\*" OR Filesystem.file_path="*\\AppData\\Local\\Microsoft\\WindowsApps\\*" OR Filesystem.file_path="*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*") by host Filesystem.user Filesystem.process_name Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| where NOT match(user,"\\$$")
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileRenamed")
| where InitiatingProcessFileName in~ ("winrar.exe","rar.exe","unrar.exe","7zfm.exe","7zg.exe","7z.exe","bandizip.exe")
| where FolderPath has_any (
    @"\Microsoft\Windows\Start Menu\Programs\Startup\",
    @"\Start Menu\Programs\Startup\",
    @"\System32\Tasks\",
    @"\AppData\Local\Microsoft\WindowsApps\",
    @"\AppData\Roaming\Microsoft\Windows\Recent\"
  )
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          FileName, FolderPath, SHA256,
          Archiver = InitiatingProcessFileName,
          ArchiverCmd = InitiatingProcessCommandLine,
          ArchiverPath = InitiatingProcessFolderPath
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2023-38831`, `CVE-2024-42009`, `CVE-2025-8088`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 10 use case(s) fired, 20 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
