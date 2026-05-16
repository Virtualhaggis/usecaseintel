# [CRIT] Kazuar: Anatomy of a nation-state botnet

**Source:** Microsoft Security Blog
**Published:** 2026-05-14
**Article:** https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/

## Threat Profile

Tags 
Blizzard 
Cyberespionage 
Secret Blizzard 
Content types 
Research 
Products and services 
Microsoft Defender 
Topics 
Threat intelligence 
Kazuar, a sophisticated malware family attributed to the Russian state actor Secret Blizzard , has been under constant development for years and continues to evolve in support of espionage-focused operations. Over time, Kazuar has expanded from a relatively traditional backdoor into a highly modular peer-to-peer (P2P) botnet ecosystem designed to enabl…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4`
- **SHA256:** `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9`
- **SHA256:** `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d`
- **SHA256:** `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85`
- **MD5:** `82760B84F1D703D596C79B88BA4FAC1E`

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
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1027** — Obfuscated Files or Information
- **T1559.001** — Inter-Process Communication: Component Object Model
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1218.011** — System Binary Proxy Execution: Rundll32
- **T1055.012** — Process Injection: Process Hollowing
- **T1546.003** — Event Triggered Execution: Windows Management Instrumentation Event Subscription
- **T1071.003** — Application Layer Protocol: Mail Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Kazuar (Secret Blizzard) Kernel Module IPC named pipe \\.\pipe\82760B84F1D703D596C79B88BA4FAC1E

`UC_52_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`sysmon` (EventCode=17 OR EventCode=18) PipeName="*82760B84F1D703D596C79B88BA4FAC1E*" | stats min(_time) as firstSeen max(_time) as lastSeen values(Image) as images values(PipeName) as pipes by host User | `drop_dm_object_name(Endpoint)`
```

**Defender KQL:**
```kql
// Kazuar Kernel module IPC pipe — default name is MD5("pipename-kernel-<bot ver>")
// = 82760B84F1D703D596C79B88BA4FAC1E. Variant deployments may use other 32-hex pipe names.
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType =~ "NamedPipeEvent"
| extend PipeName = coalesce(FileName, tostring(parse_json(AdditionalFields).PipeName))
| where PipeName has "82760B84F1D703D596C79B88BA4FAC1E"
   or PipeName matches regex @"(?i)\\pipe\\[a-f0-9]{32}$"   // 32-hex hash-named pipes (Kazuar pattern)
| project Timestamp, DeviceName, ActionType, PipeName,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessSHA256,
          InitiatingProcessAccountName, InitiatingProcessParentFileName, ReportId
| order by Timestamp desc
```

### [LLM] Kazuar (Secret Blizzard) Pelmeni dropper / .NET loader sample hashes on disk or in-memory

`UC_52_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(Processes.process) as cmdline values(Processes.process_path) as paths from datamodel=Endpoint.Processes where (Processes.process_hash IN ("69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85") OR Processes.parent_process_hash IN ("69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4","c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9","6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d","436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85")) by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
let KazuarHashes = dynamic([
  "69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4",
  "c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9",
  "6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d",
  "436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85"
]);
union isfuzzy=true
  ( DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (KazuarHashes) or InitiatingProcessSHA256 in (KazuarHashes)
    | project Timestamp, Source = "Process", DeviceName, ActionType, FileName, FolderPath,
              SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,
              AccountName ),
  ( DeviceFileEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (KazuarHashes)
    | project Timestamp, Source = "File", DeviceName, ActionType, FileName, FolderPath,
              SHA256, ProcessCommandLine = "",
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              AccountName = InitiatingProcessAccountName ),
  ( DeviceImageLoadEvents
    | where Timestamp > ago(30d)
    | where SHA256 in (KazuarHashes)
    | project Timestamp, Source = "ImageLoad", DeviceName, ActionType, FileName, FolderPath,
              SHA256, ProcessCommandLine = "",
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              AccountName = InitiatingProcessAccountName )
| order by Timestamp desc
```

### [LLM] Kazuar `live_in_scrcons` — scrcons.exe (WMI Event Consumer) reaching public C2 or hosting unsigned modules

`UC_52_10` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstSeen max(_time) as lastSeen values(All_Traffic.dest_ip) as destIPs values(All_Traffic.dest_port) as destPorts values(All_Traffic.dest) as destHosts from datamodel=Network_Traffic.All_Traffic where All_Traffic.app="scrcons.exe" AND All_Traffic.dest_category!="internal" by host All_Traffic.user | where count > 0 | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
// Kazuar `live_in_scrcons` config option hosts the implant inside the WMI Standard Event Consumer.
// scrcons.exe legitimately runs local scripts — it should NEVER egress to the public internet
// or load DLLs from user-writable paths.
let ScrconsEgress =
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "scrcons.exe"
    | where RemoteIPType == "Public"
    | where ActionType in ("ConnectionSuccess","ConnectionAttempt","HttpConnectionInspected")
    | project Timestamp, Signal = "PublicEgress", DeviceName, InitiatingProcessFileName,
              InitiatingProcessCommandLine, InitiatingProcessAccountName,
              RemoteIP, RemotePort, RemoteUrl,
              InitiatingProcessParentFileName;
let ScrconsLoadsNonMs =
    DeviceImageLoadEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFileName =~ "scrcons.exe"
    | where FolderPath has_any (@"\AppData\", @"\Users\Public\", @"\ProgramData\", @"\Temp\", @"\Windows\Tasks\")
    | where FileName endswith ".dll"
    | project Timestamp, Signal = "NonMsDllLoad", DeviceName,
              InitiatingProcessFileName,
              InitiatingProcessCommandLine,
              InitiatingProcessAccountName = InitiatingProcessAccountName,
              RemoteIP = "", RemotePort = int(null), RemoteUrl = FolderPath,
              InitiatingProcessParentFileName = "";
union ScrconsEgress, ScrconsLoadsNonMs
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

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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

### Article-specific behavioural hunt — Kazuar: Anatomy of a nation-state botnet

`UC_52_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Kazuar: Anatomy of a nation-state botnet ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("hpbprndiloc.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("hpbprndiloc.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Kazuar: Anatomy of a nation-state botnet
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("hpbprndiloc.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("hpbprndiloc.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `69908f05b436bd97baae56296bf9b9e734486516f9bb9938c2b8752e152315d4`, `c1f278f88275e07cc03bd390fe1cbeedd55933110c6fd16de4187f4c4aaf42b9`, `6eb31006ca318a21eb619d008226f08e287f753aec9042269203290462eaa00d`, `436cfce71290c2fc2f2c362541db68ced6847c66a73b55487e5e5c73b0636c85`, `82760B84F1D703D596C79B88BA4FAC1E`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
