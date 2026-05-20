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
- **T1059.005** — Command and Scripting Interpreter: Visual Basic
- **T1566.001** — Phishing: Spearphishing Attachment
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1029** — Scheduled Transfer
- **T1547.001** — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **T1203** — Exploitation for Client Execution
- **T1053.005** — Scheduled Task/Job: Scheduled Task
- **T1572** — Protocol Tunneling
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1219** — Remote Access Software
- **T1071** — Application Layer Protocol

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] PicassoLoader JavaScript executed by WScript from RAR-extracted Downloads/Temp path

`UC_77_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Processes.process) as cmdlines, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("winrar.exe","winrar64.exe","7zg.exe","7zfm.exe","explorer.exe") AND Processes.process_name IN ("wscript.exe","cscript.exe") AND (Processes.process LIKE "%.js%" OR Processes.process LIKE "%.vbs%" OR Processes.process LIKE "%.jse%" OR Processes.process LIKE "%.vbe%") AND (Processes.process LIKE "%\\Downloads\\%" OR Processes.process LIKE "%\\Temp\\%" OR Processes.process LIKE "%\\AppData\\%") by host Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | search NOT user IN ("*$","SYSTEM","LOCAL SERVICE","NETWORK SERVICE") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winrar.exe","winrar64.exe","7zg.exe","7zfm.exe","explorer.exe","rar.exe","unrar.exe")
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine has_any (".js",".jse",".vbs",".vbe")
| where ProcessCommandLine has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\", @"\AppData\Roaming\")
| where AccountName !endswith "$"
| where AccountName !in~ ("system","local service","network service")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] PicassoLoader 10-minute periodic fingerprint beacon from wscript/cscript

`UC_77_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("wscript.exe","cscript.exe") AND All_Traffic.dest_category!="internal" by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest _time span=10m | `drop_dm_object_name(All_Traffic)` | stats dc(_time) as beacon_buckets, min(_time) as firstTime, max(_time) as lastTime, count as conn_total by src user app dest | eval duration_min=(lastTime-firstTime)/60 | eval cadence_min=if(beacon_buckets>1,duration_min/(beacon_buckets-1),0) | where beacon_buckets>=6 AND cadence_min>=8 AND cadence_min<=12 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wscript.exe","cscript.exe")
| where RemoteIPType == "Public"
| where isnotempty(RemoteIP)
| extend Bucket = bin(Timestamp, 10m)
| summarize Beacons = dcount(Bucket),
            Connections = count(),
            FirstSeen = min(Timestamp),
            LastSeen  = max(Timestamp),
            Destinations = make_set(RemoteUrl, 5),
            DestPorts = make_set(RemotePort, 5)
            by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP
| extend DurationMin = datetime_diff('minute', LastSeen, FirstSeen)
| extend CadenceMin = iff(Beacons > 1, todouble(DurationMin) / (Beacons - 1), 0.0)
| where Beacons >= 6                 // at least an hour of beacons
| where CadenceMin between (8.0 .. 12.0)  // ~10-minute periodicity per ESET report
| project DeviceName, InitiatingProcessFileName, RemoteIP, DestPorts, Destinations, Beacons, Connections, CadenceMin, FirstSeen, LastSeen
| order by Beacons desc
```

### [LLM] WinRAR CVE-2025-8088 directory traversal: archive process writes to Startup folder

`UC_77_9` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Filesystem.file_path) as paths, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("winrar.exe","winrar64.exe","rar.exe","unrar.exe","7zg.exe","7zfm.exe","7z.exe") AND (Filesystem.file_path LIKE "%\\Start Menu\\Programs\\Startup\\%" OR Filesystem.file_path LIKE "%\\System32\\Tasks\\%" OR Filesystem.file_path LIKE "%\\Windows\\Tasks\\%") AND Filesystem.action="created" by host Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileCreated"
| where InitiatingProcessFileName in~ ("winrar.exe","winrar64.exe","rar.exe","unrar.exe","7zg.exe","7zfm.exe","7z.exe")
| where FolderPath has_any (
    @"\Microsoft\Windows\Start Menu\Programs\Startup\",
    @"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\",
    @"\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\",
    @"\Windows\System32\Tasks\",
    @"\Windows\Tasks\"
  )
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessVersionInfoProductVersion, InitiatingProcessCommandLine, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] ZeroSSH backdoor: userland process opens outbound SSH and spawns cmd.exe

`UC_77_10` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as ssh_conn, values(All_Traffic.dest) as ssh_dests from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port IN (22,2222) AND NOT (All_Traffic.app IN ("ssh.exe","sftp.exe","scp.exe","putty.exe","plink.exe","git.exe","openssh.exe","code.exe","WindowsTerminal.exe")) by host All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.process_path | `drop_dm_object_name(All_Traffic)` | search process_path IN ("*\\Users\\*","*\\ProgramData\\*","*\\AppData\\*","*\\Temp\\*","*\\Public\\*") | join host app [| tstats summariesonly=true count as cmd_count, values(Processes.process) as cmd_cmdlines from datamodel=Endpoint.Processes where Processes.process_name="cmd.exe" by host Processes.parent_process_name | `drop_dm_object_name(Processes)` | rename parent_process_name as app] | where cmd_count > 0
```

**Defender KQL:**
```kql
let SshProcs = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort in (22, 2222)
    | where RemoteIPType == "Public"
    | where InitiatingProcessFileName !in~ ("ssh.exe","sftp.exe","scp.exe","putty.exe","plink.exe","git.exe","git-remote-ssh.exe","openssh.exe","code.exe","WindowsTerminal.exe","msedge.exe","chrome.exe")
    | where InitiatingProcessFolderPath has_any (@"\Users\", @"\AppData\", @"\ProgramData\", @"\Temp\", @"\Public\")
    | where InitiatingProcessVersionInfoCompanyName !has_any ("Microsoft","OpenSSH","PuTTY","GitForWindows")
    | summarize SshConn = count(), SshDests = make_set(RemoteIP, 5)
              by DeviceId, DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, InitiatingProcessAccountName;
let CmdSpawns = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "cmd.exe"
    | where InitiatingProcessFolderPath has_any (@"\Users\", @"\AppData\", @"\ProgramData\", @"\Temp\", @"\Public\")
    | summarize CmdSpawnCount = count(), CmdSamples = make_set(ProcessCommandLine, 5)
              by DeviceId, InitiatingProcessId, InitiatingProcessFileName;
SshProcs
| join kind=inner (CmdSpawns) on DeviceId, InitiatingProcessId, InitiatingProcessFileName
| where InitiatingProcessAccountName !endswith "$"
| project DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA256, SshDests, SshConn, CmdSpawnCount, CmdSamples
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

Severity classified as **CRIT** based on: CVE present, 11 use case(s) fired, 24 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
