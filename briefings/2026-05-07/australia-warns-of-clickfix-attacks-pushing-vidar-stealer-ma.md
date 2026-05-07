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


ClickFix is a social engineering attack technique that tricks users into executing malicious commands, usually through fake CAPTCHA or browser verification prompts displayed on comp…

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
- **T1102.001** — Web Service: Dead Drop Resolver
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Vidar Stealer dead-drop URL fetch via Steam profile or Telegram by non-browser process

`UC_1_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_url) as dest_url values(All_Traffic.user) as user values(All_Traffic.dest_ip) as dest_ip from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_url="*steamcommunity.com/profiles/*" OR All_Traffic.dest_url="*t.me/*" OR All_Traffic.dest_url="*telegram.me/*") AND NOT All_Traffic.app IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","Steam.exe","steamwebhelper.exe","Telegram.exe","Updater.exe") by host All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)` | rename app as process_name | sort - firstTime
```

**Defender KQL:**
```kql
let _browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","Steam.exe","steamwebhelper.exe","Telegram.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where isnotempty(RemoteUrl)
| where RemoteUrl matches regex @"(?i)(steamcommunity\.com/profiles/[0-9]{15,20}|(?:t|telegram)\.me/[A-Za-z0-9_]{3,32})"
| where InitiatingProcessFileName !in~ (_browsers)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### [LLM] ClickFix Run-dialog spawn followed by Vidar Steam/Telegram dead-drop fetch within 15 minutes

`UC_1_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as ClickFixTime values(Processes.process) as ClickFixCmd values(Processes.process_name) as ClickFixChild values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.parent_process_name="explorer.exe" AND Processes.process_name IN ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe","cscript.exe") AND (Processes.process="*DownloadString*" OR Processes.process="*DownloadFile*" OR Processes.process="*Invoke-Expression*" OR Processes.process="*Invoke-WebRequest*" OR Processes.process="*iwr *" OR Processes.process="*IEX *" OR Processes.process="* IEX(" OR Processes.process="*FromBase64String*" OR Processes.process="*-EncodedCommand*" OR Processes.process="* -enc *" OR Processes.process="*-w hidden*" OR Processes.process="*WindowStyle Hidden*" OR Processes.process="*mshta*http*" OR Processes.process="*certutil*-urlcache*") by host Processes.user | `drop_dm_object_name(Processes)` | join type=inner host [ | tstats `summariesonly` min(_time) as NetTime values(All_Traffic.dest_url) as dest_url values(All_Traffic.app) as net_process from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_url="*steamcommunity.com/profiles/*" OR All_Traffic.dest_url="*t.me/*" OR All_Traffic.dest_url="*telegram.me/*") AND NOT All_Traffic.app IN ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","Steam.exe","steamwebhelper.exe","Telegram.exe") by host | `drop_dm_object_name(All_Traffic)` ] | eval delay_seconds = NetTime - ClickFixTime | where delay_seconds >= 0 AND delay_seconds <= 900 | table host user ClickFixTime ClickFixChild ClickFixCmd NetTime net_process dest_url delay_seconds | sort - ClickFixTime
```

**Defender KQL:**
```kql
let LookbackDays = 7d;
let WindowMin = 15;
let _browsers = dynamic(["chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","iexplore.exe","Steam.exe","steamwebhelper.exe","Telegram.exe"]);
let ClickFixSpawn =
    DeviceProcessEvents
    | where Timestamp > ago(LookbackDays)
    | where InitiatingProcessFileName =~ "explorer.exe"
    | where FileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","wscript.exe","cscript.exe")
    | where ProcessCommandLine has_any ("DownloadString","DownloadFile","Invoke-Expression","Invoke-WebRequest","IEX(","iwr ","FromBase64String","-EncodedCommand","-enc ","-EC ","WindowStyle Hidden","-w hidden","-w 1","mshta http","certutil -urlcache","curl http")
    | where AccountName !endswith "$"
    | project ClickFixTime=Timestamp, DeviceId, DeviceName, AccountName, ChildFile=FileName, ChildCmd=ProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(LookbackDays)
| where isnotempty(RemoteUrl)
| where RemoteUrl matches regex @"(?i)(steamcommunity\.com/profiles/[0-9]{15,20}|(?:t|telegram)\.me/[A-Za-z0-9_]{3,32})"
| where InitiatingProcessFileName !in~ (_browsers)
| project NetTime=Timestamp, DeviceId, NetProcess=InitiatingProcessFileName, NetCmd=InitiatingProcessCommandLine, RemoteUrl, RemoteIP
| join kind=inner ClickFixSpawn on DeviceId
| where NetTime between (ClickFixTime .. ClickFixTime + WindowMin * 1m)
| extend DelayMin = datetime_diff('minute', NetTime, ClickFixTime)
| project ClickFixTime, NetTime, DelayMin, DeviceName, AccountName, ChildFile, ChildCmd, NetProcess, NetCmd, RemoteUrl, RemoteIP
| order by ClickFixTime desc
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

Severity classified as **CRIT** based on: 7 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
