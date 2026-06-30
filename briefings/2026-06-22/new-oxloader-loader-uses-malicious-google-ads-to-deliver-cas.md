# [HIGH] New OXLOADER Loader Uses Malicious Google Ads to Deliver CastleStealer

**Source:** The Hacker News
**Published:** 2026-06-22
**Article:** https://thehackernews.com/2026/06/new-oxloader-loader-uses-malicious.html

## Threat Profile

New OXLOADER Loader Uses Malicious Google Ads to Deliver CastleStealer 
 Ravie Lakshmanan  Jun 22, 2026 Malvertising / Endpoint Security 
Cybersecurity researchers have disclosed details of a new campaign that delivers CastleStealer by means of a previously unreported malware loader dubbed OXLOADER .
According to Elastic Security Labs, the campaign leverages malicious Google Ads as a starting point to distribute the malware. Evidence indicates that the threat actor is likely Russian-speaking a…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `89.124.95.161`
- **IPv4 (defanged):** `89.124.115.82`
- **Domain (defanged):** `node-js.prentiva99.info`
- **Domain (defanged):** `app.miloyannopoulos.com`
- **SHA256:** `fdfc7831e5c24cfa80152860dfe8c056ba079f7df1393bf6bb7b18ed974eda37`
- **SHA256:** `de4f51649ec1a33071854aefe93ffb3fc225e19f802d8dd914676dd5dfef2615`
- **SHA256:** `9a9939dff297997732aaade9b243d695632cbd64033c5fbcb9de3d09b7e6c28d`
- **SHA256:** `c85f2765a6c3c3f3907c17e57df12f8f68826f74bff3bbfd272af50666d065fe`
- **SHA256:** `4ec9d9d4d10ad78fc6d7bda7cb17d52984878ccd2dd4302fd1cef152313b9741`
- **SHA256:** `39019279686c820c3af5684012a0085a7e2109f612c9fab886dd0577ace5b5c6`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1189** — Drive-by Compromise
- **T1583.008** — Acquire Infrastructure: Malvertising
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1105** — Ingress Tool Transfer
- **T1548.002** — Abuse Elevation Control Mechanism: Bypass User Account Control
- **T1574.002** — Hijack Execution Flow: DLL Side-Loading
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### REF8372 malvertising delivery domains (prentiva99.info / miloyannopoulos.com) contacted

`UC_94_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (Network_Traffic.All_Traffic.dest IN ("node-js.prentiva99.info","prentiva99.info","app.miloyannopoulos.com","miloyannopoulos.com")) by Network_Traffic.src Network_Traffic.dest Network_Traffic.dest_port | `drop_dm_object_name(Network_Traffic.All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any ("prentiva99.info","miloyannopoulos.com")
    or RemoteUrl has_any ("BATPackageBuilderSetup.bat","BATPackageBulderSetup.bat","aBsvwbdas.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### OXLOADER fake-installer batch spawns PowerShell -Verb RunAs to fetch Storj payload

`UC_94_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Endpoint.Processes.process_name IN ("powershell.exe","pwsh.exe")) AND Endpoint.Processes.process="*RunAs*" AND (Endpoint.Processes.process="*storjshare.io*" OR Endpoint.Processes.process="*aBsvwbdas.exe*" OR Endpoint.Processes.process="*BATPackageBu*Setup*") by Endpoint.Processes.dest Endpoint.Processes.user Endpoint.Processes.parent_process_name Endpoint.Processes.process Endpoint.Processes.process_name | `drop_dm_object_name(Endpoint.Processes)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine has "RunAs"
| where ProcessCommandLine has_any ("storjshare.io","aBsvwbdas.exe","BATPackageBuilderSetup","BATPackageBulderSetup")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### OXLOADER DLL side-load: Windows dui70.dll loaded from a non-system path

`UC_94_9` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Endpoint.Filesystem.file_name="dui70.dll" AND NOT (Endpoint.Filesystem.file_path IN ("*\\Windows\\System32\\*","*\\Windows\\WinSxS\\*","*\\Windows\\SysWOW64\\*")) by Endpoint.Filesystem.dest Endpoint.Filesystem.file_path Endpoint.Filesystem.file_name | `drop_dm_object_name(Endpoint.Filesystem)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName =~ "dui70.dll"
| where not(FolderPath has @"\Windows\System32\") and not(FolderPath has @"\Windows\WinSxS\") and not(FolderPath has @"\Windows\SysWOW64\")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, LoadedDll = FileName, LoadedFrom = FolderPath, SHA256, InitiatingProcessSHA256
| order by Timestamp desc
```

### CastleStealer C2 beacon to 89.124.95.161 / 89.124.115.82

`UC_94_10` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (Network_Traffic.All_Traffic.dest IN ("89.124.95.161","89.124.115.82")) by Network_Traffic.src Network_Traffic.dest Network_Traffic.dest_port Network_Traffic.app | `drop_dm_object_name(Network_Traffic.All_Traffic)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in ("89.124.95.161","89.124.115.82")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, InitiatingProcessSHA256
| order by Timestamp desc
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

### Article-specific behavioural hunt — New OXLOADER Loader Uses Malicious Google Ads to Deliver CastleStealer

`UC_94_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — New OXLOADER Loader Uses Malicious Google Ads to Deliver CastleStealer ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — New OXLOADER Loader Uses Malicious Google Ads to Deliver CastleStealer
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `89.124.95.161`, `89.124.115.82`, `node-js.prentiva99.info`, `app.miloyannopoulos.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `fdfc7831e5c24cfa80152860dfe8c056ba079f7df1393bf6bb7b18ed974eda37`, `de4f51649ec1a33071854aefe93ffb3fc225e19f802d8dd914676dd5dfef2615`, `9a9939dff297997732aaade9b243d695632cbd64033c5fbcb9de3d09b7e6c28d`, `c85f2765a6c3c3f3907c17e57df12f8f68826f74bff3bbfd272af50666d065fe`, `4ec9d9d4d10ad78fc6d7bda7cb17d52984878ccd2dd4302fd1cef152313b9741`, `39019279686c820c3af5684012a0085a7e2109f612c9fab886dd0577ace5b5c6`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
