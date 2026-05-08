# [CRIT] Australia warns of ClickFix attacks pushing Vidar Stealer malware

**Source:** BleepingComputer
**Published:** 2026-05-07
**Article:** https://www.bleepingcomputer.com/news/security/australia-warns-of-clickfix-attacks-pushing-vidar-stealer-malware/

## Threat Profile

Australia warns of ClickFix attacks pushing Vidar Stealer malware 
By Bill Toulas 
May 7, 2026
02:00 PM
0 
The Australian Cyber Security Center (ACSC) is warning organizations of an ongoing malware campaign using the ClickFix social engineering technique to distribute  the Vidar Stealer info-stealing malware.
ClickFix is a social engineering attack technique that tricks users into executing malicious commands, usually through fake CAPTCHA or browser verification prompts displayed on compromised …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1566.002** — Phishing: Spearphishing Link
- **T1218.005** — System Binary Proxy Execution: Mshta
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1070.004** — Indicator Removal: File Deletion
- **T1140** — Deobfuscate/Decode Files or Information
- **T1564.001** — Hide Artifacts: Hidden Files and Directories

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] ClickFix Run-dialog PowerShell/mshta paste delivering Vidar Stealer

`UC_31_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="explorer.exe" AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe") AND (Processes.process="*IEX*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*Invoke-WebRequest*" OR Processes.process="*iwr *" OR Processes.process="*DownloadString*" OR Processes.process="*DownloadFile*" OR Processes.process="*Net.WebClient*" OR Processes.process="*FromBase64String*" OR Processes.process="*-EncodedCommand*" OR Processes.process="*-enc *" OR Processes.process="*-ec *" OR Processes.process="*mshta*http*" OR Processes.process="*curl *http*" OR Processes.process="*certutil*-urlcache*" OR Processes.process="*msiexec*/i*http*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe")
| where ProcessCommandLine has_any ("IEX","Invoke-Expression","Invoke-WebRequest","iwr ","DownloadString","DownloadFile","Net.WebClient","FromBase64String","-EncodedCommand","-enc ","-ec ","curl http","certutil -urlcache","mshta http","msiexec /i http")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Vidar Stealer dead-drop C2 resolution via Steam profile or Telegram URL

`UC_31_6` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url="*steamcommunity.com/profiles/*" OR All_Traffic.url="*steamcommunity.com/id/*" OR All_Traffic.url="*t.me/*" OR All_Traffic.url="*telegram.me/*" OR All_Traffic.url="*telegra.ph/*" OR All_Traffic.dest="steamcommunity.com" OR All_Traffic.dest="t.me" OR All_Traffic.dest="telegram.me" OR All_Traffic.dest="telegra.ph") AND All_Traffic.app!="chrome.exe" AND All_Traffic.app!="msedge.exe" AND All_Traffic.app!="firefox.exe" AND All_Traffic.app!="brave.exe" AND All_Traffic.app!="opera.exe" AND All_Traffic.app!="iexplore.exe" AND All_Traffic.app!="steam.exe" AND All_Traffic.app!="steamwebhelper.exe" AND All_Traffic.app!="telegram.exe" AND All_Traffic.app!="discord.exe" AND All_Traffic.app!="slack.exe" AND All_Traffic.app!="msteams.exe" AND All_Traffic.app!="outlook.exe" by All_Traffic.src All_Traffic.user All_Traffic.app All_Traffic.dest All_Traffic.url | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let _browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","iexplore.exe","opera.exe","operagx.exe","vivaldi.exe","arc.exe","safari.exe"]);
let _legit_clients = dynamic(["steam.exe","steamwebhelper.exe","steamservice.exe","telegram.exe","telegramdesktop.exe","discord.exe","slack.exe","msteams.exe","outlook.exe","msedgewebview2.exe","whatsapp.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where RemoteUrl has_any ("steamcommunity.com/profiles/","steamcommunity.com/id/","t.me/","telegram.me/","telegra.ph/")
| where InitiatingProcessFileName !in~ (_browsers)
| where InitiatingProcessFileName !in~ (_legit_clients)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, InitiatingProcessSHA256
| order by Timestamp desc
```

### [LLM] Vidar Stealer self-deletion: PE in user-writable temp deletes itself within minutes of execution

`UC_31_7` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where (Processes.process_path="*\\AppData\\Local\\Temp\\*" OR Processes.process_path="*\\AppData\\Roaming\\*" OR Processes.process_path="*\\Users\\Public\\*" OR Processes.process_path="*\\ProgramData\\*" OR Processes.process_path="*\\Windows\\Temp\\*") AND Processes.user!="*$" by _time Processes.dest Processes.user Processes.process_path Processes.process_name Processes.process_hash | rename Processes.* as * | rename _time as ExecTime | join type=inner dest [ | tstats summariesonly=true count from datamodel=Endpoint.Filesystem where Filesystem.action="deleted" AND (Filesystem.file_path="*\\AppData\\Local\\Temp\\*" OR Filesystem.file_path="*\\Users\\Public\\*" OR Filesystem.file_path="*\\ProgramData\\*") by _time Filesystem.dest Filesystem.file_path Filesystem.process_name | rename Filesystem.* as *, _time as DelTime | rename file_path as DeletedPath ] | where DeletedPath==process_path AND DelTime>=ExecTime AND DelTime<=ExecTime+300 | table ExecTime DelTime dest user process_path process_name process_hash
```

**Defender KQL:**
```kql
let _drops = dynamic([@"\AppData\Local\Temp\", @"\AppData\Roaming\", @"\Users\Public\", @"\ProgramData\", @"\Windows\Temp\"]);
let _execs = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where AccountName !endswith "$"
    | where FolderPath has_any (_drops)
    | where FileName endswith ".exe"
    | project ExecTime = Timestamp, DeviceId, DeviceName, ExecAccount = AccountName, ExecPath = FolderPath, ExecFile = FileName, ExecSha = SHA256, ExecCmd = ProcessCommandLine, ExecParent = InitiatingProcessFileName;
let _deletes = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileDeleted"
    | where FolderPath has_any (_drops)
    | where FileName endswith ".exe"
    | project DelTime = Timestamp, DeviceId, DelPath = FolderPath, DelFile = FileName, DelInitiator = InitiatingProcessFileName, DelInitiatorCmd = InitiatingProcessCommandLine;
_execs
| join kind=inner _deletes on DeviceId
| where DelPath =~ ExecPath
| where DelTime between (ExecTime .. ExecTime + 5m)
| project ExecTime, DelTime, DelaySec = datetime_diff('second', DelTime, ExecTime), DeviceName, ExecAccount, ExecPath, ExecSha, ExecParent, ExecCmd, DelInitiator, DelInitiatorCmd
| order by ExecTime desc
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


## Why this matters

Severity classified as **CRIT** based on: 8 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
