# [CRIT] Mini Shai-Hulud Hits AntV: 300+ Malicious npm Packages Published via Compromised Maintainer Account

**Source:** Snyk
**Published:** 2026-05-18
**Article:** https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
May 18, 2026
0 mins read A supply chain attack affecting the @antv data visualization ecosystem and related npm packages is actively spreading through the npm registry. The attack, attributed to a threat group called TeamPCP and branded as another wave of the Mini Shai-Hulud campaign, published more than 300 malicious package versions across 323 packages in a 22-minute automated burst on May 19, 2026. The packages collectively represent approximate…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `185.95.159.32`
- **Domain (defanged):** `m-kosche.com`
- **Domain (defanged):** `t.m-kosche.com`
- **Domain (defanged):** `filev2.getsession.org`
- **SHA256:** `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`
- **SHA256:** `fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142`
- **SHA1:** `783b4019fc5b942a29846132d28441c8fc31bed8`
- **MD5:** `b06b126b9e26af03a7ef2f8b8e90d446`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1543.001** — Persistence (article-specific)
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution
- **T1543.002** — Create or Modify System Process: Systemd Service
- **T1102.002** — Web Service: Bidirectional Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1102.003** — Web Service: One-Way Communication

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Mini Shai-Hulud npm preinstall hook spawning bun runtime

`UC_393_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("npm","npm.exe","npm-cli.js","node","node.exe","npx.exe","yarn.exe","pnpm.exe") OR Processes.parent_process IN ("*npm install*","*npm ci*","*yarn install*","*pnpm install*")) AND (Processes.process_name="bun" OR Processes.process_name="bun.exe") AND Processes.process="*index.js*" by host, user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process, Processes.process_path | `drop_dm_object_name(Processes)` | where user!="SYSTEM" AND NOT match(user,"\$$")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("npm","npm.exe","node","node.exe","npx.exe","yarn.exe","pnpm.exe")
    or InitiatingProcessCommandLine has_any ("npm install","npm ci","yarn install","pnpm install")
| where FileName in~ ("bun","bun.exe")
| where ProcessCommandLine has "index.js"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### Mini Shai-Hulud Claude Code SessionStart hook injection via npm install

`UC_393_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*/.claude/settings.json" OR Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*/.claude/setup.mjs" OR Filesystem.file_path="*\\.claude\\settings.local.json" OR Filesystem.file_path="*/.claude/settings.local.json") AND Filesystem.process_name IN ("npm","npm.exe","node","node.exe","bun","bun.exe","yarn.exe","pnpm.exe","npx.exe") by host, user, Filesystem.process_name, Filesystem.process, Filesystem.file_path, Filesystem.action | `drop_dm_object_name(Filesystem)` | where user!="SYSTEM"
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FolderPath has @"\.claude\" or FolderPath has "/.claude/")
| where FileName in~ ("settings.json","setup.mjs","settings.local.json")
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where InitiatingProcessFileName in~ ("npm.exe","npm","node.exe","node","bun.exe","bun","yarn.exe","pnpm.exe","npx.exe")
   or InitiatingProcessParentFileName in~ ("npm.exe","node.exe","bun.exe","npm","node","bun")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          ParentProcess = InitiatingProcessParentFileName,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          FolderPath, FileName, SHA256
| order by Timestamp desc
```

### VS Code tasks.json folderOpen persistence written by npm install chain

`UC_393_10` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*/.vscode/tasks.json") AND Filesystem.process_name IN ("npm","npm.exe","node","node.exe","bun","bun.exe","yarn.exe","pnpm.exe","npx.exe") by host, user, Filesystem.process_name, Filesystem.process, Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where user!="SYSTEM"
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FolderPath has @"\.vscode\" or FolderPath has "/.vscode/")
| where FileName =~ "tasks.json"
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName in~ ("npm.exe","npm","node.exe","node","bun.exe","bun","yarn.exe","pnpm.exe","npx.exe")
   or InitiatingProcessParentFileName in~ ("npm.exe","node.exe","bun.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Writer = InitiatingProcessFileName,
          WriterCmd = InitiatingProcessCommandLine,
          FolderPath, FileName
| order by Timestamp desc
```

### Mini Shai-Hulud Linux daemon persistence: kitty/cat.py and systemd user service

`UC_393_11` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/.local/share/kitty/cat.py" OR (Filesystem.file_path="*/.config/systemd/user/*" AND Filesystem.file_path="*.service")) AND Filesystem.process_name IN ("npm","node","bun","yarn","pnpm","npx","sh","bash","dash","zsh") by host, user, Filesystem.process_name, Filesystem.process, Filesystem.file_path | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where (FolderPath has "/.local/share/kitty/" and FileName =~ "cat.py")
    or (FolderPath has "/.config/systemd/user/" and FileName endswith ".service")
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessFileName in~ ("npm","node","bun","yarn","pnpm","npx","sh","bash","dash","zsh")
   or InitiatingProcessParentFileName in~ ("npm","node","bun")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          Writer = InitiatingProcessFileName,
          ParentWriter = InitiatingProcessParentFileName,
          WriterCmd = InitiatingProcessCommandLine,
          FolderPath, FileName
| order by Timestamp desc
```

### Mini Shai-Hulud C2 backchannel: python polling GitHub commit search for 'firedalazer'

`UC_393_12` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.dest="api.github.com" AND (Web.url="*search/commits*" OR Web.url="*firedalazer*") AND (Web.http_user_agent="python-requests*") by host, src, src_user, Web.url, Web.http_method, Web.http_user_agent | `drop_dm_object_name(Web)` | stats count min(firstTime) as firstTime max(lastTime) as lastTime dc(url) as distinct_urls values(http_user_agent) as ua by host, src, src_user | where count >= 4
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "api.github.com"
| where InitiatingProcessFileName in~ ("python","python.exe","python3","python3.exe")
| where InitiatingProcessCommandLine has_any ("cat.py",".local/share/kitty","kitty\\cat.py","firedalazer")
| summarize PollCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SampleCmd = any(InitiatingProcessCommandLine)
          by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP
| where PollCount >= 4
| order by LastSeen desc
```

### Mini Shai-Hulud GitHub dead-drop exfiltration via python-requests/2.31.0

`UC_393_13` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.dest="api.github.com" AND Web.http_user_agent="python-requests/2.31.0*" AND Web.http_method IN ("POST","PUT","PATCH") AND (Web.url="*/user/repos*" OR Web.url="*/contents/results-*" OR Web.url="*sardaukar*" OR Web.url="*fremen*" OR Web.url="*atreides*" OR Web.url="*sandworm*" OR Web.url="*ornithopter*" OR Web.url="*stillsuit*") by host, src, src_user, Web.url, Web.http_method | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
let SuspiciousPython = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("python.exe","python","python3.exe","python3")
    | where ProcessCommandLine has_any ("cat.py",".local/share/kitty","kitty\\cat.py")
    | project DeviceId, ProcessId, PyStart=Timestamp, PyCmd=ProcessCommandLine;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "api.github.com"
| where InitiatingProcessFileName in~ ("python.exe","python","python3.exe","python3")
| join kind=inner SuspiciousPython on DeviceId, $left.InitiatingProcessId == $right.ProcessId
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            SampleUrls = make_set(RemoteUrl, 5), SampleCmd = any(PyCmd)
          by DeviceName, InitiatingProcessAccountName, RemoteIP
| order by LastSeen desc
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

### Article-specific behavioural hunt — Mini Shai-Hulud Hits AntV: 300+ Malicious npm Packages Published via Compromised

`UC_393_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Mini Shai-Hulud Hits AntV: 300+ Malicious npm Packages Published via Compromised ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("timeago.js","canvas-nest.js","index.js","token-monitor.sh","gh-token-monitor.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/LaunchAgents/com.user.kitty-monitor.plist*" OR Filesystem.file_path="*/dev/null*" OR Filesystem.file_name IN ("timeago.js","canvas-nest.js","index.js","token-monitor.sh","gh-token-monitor.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Mini Shai-Hulud Hits AntV: 300+ Malicious npm Packages Published via Compromised
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("timeago.js", "canvas-nest.js", "index.js", "token-monitor.sh", "gh-token-monitor.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/LaunchAgents/com.user.kitty-monitor.plist", "/dev/null") or FileName in~ ("timeago.js", "canvas-nest.js", "index.js", "token-monitor.sh", "gh-token-monitor.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `185.95.159.32`, `m-kosche.com`, `t.m-kosche.com`, `filev2.getsession.org`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`, `fb5c97557230a27460fdab01fafcfabeaa49590bafd5b6ef30501aa9e0a51142`, `783b4019fc5b942a29846132d28441c8fc31bed8`, `b06b126b9e26af03a7ef2f8b8e90d446`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 14 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
