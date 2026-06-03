# [HIGH] Hackers hijack thousands of sites for ClickFix and FakeUpdate attacks

**Source:** BleepingComputer
**Published:** 2026-06-01
**Article:** https://www.bleepingcomputer.com/news/security/hackers-hijack-thousands-of-sites-for-clickfix-and-fakeupdate-attacks/

## Threat Profile

Hackers hijack thousands of sites for ClickFix and FakeUpdate attacks 
By Bill Toulas 
June 1, 2026
06:14 PM
0 
A threat actor tracked as DriveSurge has been operating large-scale malware distribution campaigns using ClickFix and FakeUpdates techniques on compromised sites.
Thousands of websites have been compromised in DriveSurge campaigns to redirect visitors to malware-delivery infrastructure, according to researchers at cybersecurity company SilentPush.
ClickFix is a popular social engineeri…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `91.92.240.127`
- **IPv4 (defanged):** `46.226.166.57`
- **IPv4 (defanged):** `147.45.42.200`
- **IPv4 (defanged):** `147.45.42.205`
- **Domain (defanged):** `beacontrace.bond`
- **Domain (defanged):** `check.first-node.rocks`
- **Domain (defanged):** `cptoptious.com`
- **Domain (defanged):** `webgleam.info`
- **Domain (defanged):** `banerpanel.live`
- **Domain (defanged):** `testio.ecartdev.com`
- **Domain (defanged):** `newtdsone.shop`
- **Domain (defanged):** `captioto.com`
- **Domain (defanged):** `ztds.info`
- **Domain (defanged):** `maxintora.com`
- **Domain (defanged):** `ycyfugihih.cfd`
- **Domain (defanged):** `flixtrend.net`
- **Domain (defanged):** `brightson.icu`
- **Domain (defanged):** `coverlink.icu`
- **Domain (defanged):** `datumprobe.icu`
- **Domain (defanged):** `eraggifts.icu`
- **Domain (defanged):** `keyview.icu`
- **Domain (defanged):** `traceglimpse.icu`
- **Domain (defanged):** `tracekey.icu`
- **SHA256:** `90aecb370dfb1a99a1f7de0a9c6842ab1b664521fddea16b0ec9a91f322646fc`
- **SHA256:** `7aa15de93cf85729ddf970e8d7897f69ece3ca29608f73e784a9ba40c9cea18d`
- **SHA256:** `8ecc7108cd679316bf5900e84f19b256dc399902cdede646493f502ac872cc1a`
- **SHA256:** `e1ce4e6222396a58d13dddfe64c1dd21f1632bcbe11d1867d44bab4fc646883a`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1071** — Application Layer Protocol
- **T1189** — Drive-by Compromise
- **T1583.008** — Acquire Infrastructure: Malvertising
- **T1204.002** — User Execution: Malicious File
- **T1036.005** — Masquerading: Match Legitimate Name or Location
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1105** — Ingress Tool Transfer
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1115** — Clipboard Data

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] DriveSurge zTDS loader script injection (t.js?site=<id>) outbound

`UC_42_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*t.js?site=*" OR Web.dest IN ("beacontrace.bond","check.first-node.rocks","cptoptious.com","webgleam.info","banerpanel.live","testio.ecartdev.com","newtdsone.shop","captioto.com","ztds.info") by Web.src Web.user Web.dest Web.url Web.http_referrer | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","safari.exe","yandex.exe")
| where (RemoteUrl has "t.js?site=")
   or RemoteUrl has_any ("beacontrace.bond","check.first-node.rocks","cptoptious.com","webgleam.info","banerpanel.live","testio.ecartdev.com","newtdsone.shop","captioto.com","ztds.info")
   or RemoteIP in ("91.92.240.127","46.226.166.57","147.45.42.200","147.45.42.205")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| order by Timestamp desc
```

### [LLM] FakeUpdates 'Browser Update.exe' drop from ZIP in user-writable path

`UC_42_6` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name="Browser Update.exe" OR Processes.process_hash IN ("90aecb370dfb1a99a1f7de0a9c6842ab1b664521fddea16b0ec9a91f322646fc","7aa15de93cf85729ddf970e8d7897f69ece3ca29608f73e784a9ba40c9cea18d","8ecc7108cd679316bf5900e84f19b256dc399902cdede646493f502ac872cc1a","e1ce4e6222396a58d13dddfe64c1dd21f1632bcbe11d1867d44bab4fc646883a") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process_path Processes.process Processes.process_hash | `drop_dm_object_name(Processes)` | where match(process_path,"(?i)\\\\(Downloads|Temp|AppData\\\\Local\\\\Temp)\\\\") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CampaignHashes = dynamic(["90aecb370dfb1a99a1f7de0a9c6842ab1b664521fddea16b0ec9a91f322646fc","7aa15de93cf85729ddf970e8d7897f69ece3ca29608f73e784a9ba40c9cea18d","8ecc7108cd679316bf5900e84f19b256dc399902cdede646493f502ac872cc1a","e1ce4e6222396a58d13dddfe64c1dd21f1632bcbe11d1867d44bab4fc646883a"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "Browser Update.exe"
    or SHA256 in (CampaignHashes)
    or InitiatingProcessSHA256 in (CampaignHashes)
| where FolderPath has_any (@"\Downloads\", @"\Temp\", @"\AppData\Local\Temp\")
    or InitiatingProcessFileName in~ ("explorer.exe","7zg.exe","7zfm.exe","winrar.exe","chrome.exe","msedge.exe","firefox.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, SHA256, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] ClickFix PowerShell pasted from browser-originated clipboard (Run dialog chain)

`UC_42_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe") AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where match(process,"(?i)(iex|invoke-expression|downloadstring|iwr|invoke-webrequest|curl\s+http|mshta\s+http|\.bond|\.shop|cptoptious|webgleam|banerpanel|newtdsone|captioto|first-node\.rocks|beacontrace)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("explorer.exe","chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","yandex.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe")
| where ProcessCommandLine has_any ("iex","Invoke-Expression","DownloadString","IWR","Invoke-WebRequest","curl http","mshta http",".bond",".shop","cptoptious","webgleam","banerpanel","newtdsone","captioto","first-node.rocks","beacontrace")
    or ProcessCommandLine matches regex @"(?i)(?:-(?:e(?:nc(?:odedcommand)?)?))\s+[A-Za-z0-9+/=]{20,}"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
```

### [LLM] DriveSurge campaign IP beaconing post-payload execution

`UC_42_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest IN ("91.92.240.127","46.226.166.57","147.45.42.200","147.45.42.205") AND All_Traffic.app!="chrome.exe" AND All_Traffic.app!="msedge.exe" AND All_Traffic.app!="firefox.exe" by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CampaignIPs = dynamic(["91.92.240.127","46.226.166.57","147.45.42.200","147.45.42.205"]);
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in (CampaignIPs)
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","vivaldi.exe","yandex.exe","safari.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### [LLM] macOS ClickFix clipboard-hijack: Terminal/osascript shell exec from browser context

`UC_42_9` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.os="macOS" AND Processes.parent_process_name IN ("Terminal","iTerm2","osascript","Safari","Google Chrome","Firefox","Brave Browser") AND Processes.process_name IN ("bash","sh","zsh","curl","osascript") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where match(process,"(?i)(curl\s+-[a-z]*s.*\|\s*(sh|bash|zsh)|base64\s+(-d|--decode)|osascript\s+-e.*do shell script|eval\s*\(.*curl)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in ((DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId))
| where InitiatingProcessFileName in~ ("Terminal","iTerm2","osascript","Safari","Google Chrome","firefox","Brave Browser","Microsoft Edge")
| where FileName in~ ("bash","sh","zsh","curl","osascript","wget")
| where ProcessCommandLine has_any ("curl -s","curl -sS","curl -fsSL","| sh","| bash","| zsh","base64 -d","base64 --decode","do shell script","eval $(curl")
   or ProcessCommandLine has_all ("curl","http","|")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `91.92.240.127`, `46.226.166.57`, `147.45.42.200`, `147.45.42.205`, `beacontrace.bond`, `check.first-node.rocks`, `cptoptious.com`, `webgleam.info` _(+15 more)_

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `90aecb370dfb1a99a1f7de0a9c6842ab1b664521fddea16b0ec9a91f322646fc`, `7aa15de93cf85729ddf970e8d7897f69ece3ca29608f73e784a9ba40c9cea18d`, `8ecc7108cd679316bf5900e84f19b256dc399902cdede646493f502ac872cc1a`, `e1ce4e6222396a58d13dddfe64c1dd21f1632bcbe11d1867d44bab4fc646883a`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 10 use case(s) fired, 15 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
