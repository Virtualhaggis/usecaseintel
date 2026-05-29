# [HIGH] Typosquatted npm Packages Steal Cloud and CI/CD Secrets From Developer Systems

**Source:** Cyber Security News
**Published:** 2026-05-29
**Article:** https://cybersecuritynews.com/typosquatted-npm-packages-steal-cloud-and-ci-cd-secrets/

## Threat Profile

Home Cyber Security News 
Typosquatted npm Packages Steal Cloud and CI/CD Secrets From Developer Systems 
By Tushar Subhra Dutta 
May 29, 2026 
A new wave of malicious software packages has been caught stealing cloud credentials and CI/CD pipeline secrets from developer machines, raising fresh alarms about the security of the open-source software supply chain. 
The attack, uncovered on May 28, 2026, shows just how easy it has become for bad actors to slip dangerous code into the hands of unsuspe…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `aab.sportsontheweb.net`
- **SHA256:** `638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d`
- **SHA256:** `77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d`
- **SHA256:** `bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1219** — Remote Access Software
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] vpmdhaj npm campaign C2 callback to aab.sportsontheweb.net (X-Supply: 1 marker)

`UC_17_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="aab.sportsontheweb.net" OR All_Traffic.dest_host="aab.sportsontheweb.net" OR All_Traffic.url="*aab.sportsontheweb.net/x.php*") by host All_Traffic.src All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| append [ | tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url from datamodel=Web.Web where (Web.url="*aab.sportsontheweb.net*" OR Web.http_user_agent="*X-Supply*" OR Web.http_request_headers="*X-Supply: 1*") by host Web.src Web.user | `drop_dm_object_name(Web)` ]
| append [ | tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(DNS.answer) as answer from datamodel=Network_Resolution.DNS where DNS.query="*aab.sportsontheweb.net*" by host DNS.src | `drop_dm_object_name(DNS)` ]
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let C2Domain = "aab.sportsontheweb.net";
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has C2Domain or RemoteUrl endswith ".sportsontheweb.net"
    | extend Source = "Network", Indicator = RemoteUrl
    | project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, Indicator, Source;
let ProcHits = DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType in ("ConnectionSuccess", "DnsConnectionInspected")
    | where RemoteUrl has C2Domain or AdditionalFields has "X-Supply: 1"
    | extend Source = "DeviceEvents", Indicator = RemoteUrl
    | project Timestamp, DeviceName, AccountName, InitiatingProcessFileName = FileName, InitiatingProcessCommandLine = ProcessCommandLine, RemoteIP, RemotePort, Indicator, Source;
union NetHits, ProcHits
| order by Timestamp desc
```

### [LLM] Node.js descendant queries AWS IMDS (169.254.169.254) or ECS task metadata (169.254.170.2)

`UC_17_9` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest_ip) as dest_ip values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as app values(All_Traffic.process) as process from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip IN ("169.254.169.254","169.254.170.2") (All_Traffic.app IN ("node.exe","npm.exe","bun.exe","node","npm","bun") OR All_Traffic.process IN ("node.exe","npm.exe","bun.exe","node","npm","bun")) by host All_Traffic.src All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let TargetIPs = dynamic(["169.254.169.254", "169.254.170.2"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in (TargetIPs)
| where InitiatingProcessFileName has_any ("node.exe","npm.exe","npx.exe","bun.exe","node","npm","bun")
   or InitiatingProcessParentFileName has_any ("node.exe","npm.exe","bun.exe")
   or InitiatingProcessCommandLine has_any ("opensearch_init.js","ai_init.js","payload.bin","preinstall.js","setup.mjs")
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, DeviceType, OSPlatform, IsInternetFacing) by DeviceId
  ) on DeviceId
| where OSPlatform !contains "Linux" or IsInternetFacing == false
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### [LLM] vpmdhaj campaign stager / payload artifact written under node_modules

`UC_17_10` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_hash) as file_hash values(Filesystem.process_name) as process_name from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("opensearch_init.js","ai_init.js","payload.bin","payload.gz","preinstall.js","setup.mjs") AND Filesystem.file_path="*node_modules*") OR Filesystem.file_hash IN ("638788AFC4F1B5860A328312CAF5895ABD5F5632D28A4F2A85B09076E270D15D","77D92EFE7AF3547F71FD41D4A884872D66B1BE9499EAA637E91EAC866911694D","BFA149694EC6411C23936311A999163ADE54D6F38E2F4B0E3CFB8CB67BD7CFAA") by host Filesystem.user Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
let BadHashes = dynamic(["638788AFC4F1B5860A328312CAF5895ABD5F5632D28A4F2A85B09076E270D15D","77D92EFE7AF3547F71FD41D4A884872D66B1BE9499EAA637E91EAC866911694D","BFA149694EC6411C23936311A999163ADE54D6F38E2F4B0E3CFB8CB67BD7CFAA"]);
let BadNames = dynamic(["opensearch_init.js","ai_init.js","payload.bin","payload.gz","preinstall.js","setup.mjs"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where SHA256 in (BadHashes)
     or (FileName in~ (BadNames) and FolderPath has "node_modules")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, SHA256, FileSize
| order by Timestamp desc
```

### [LLM] npm install lifecycle hook spawning detached Bun / Node child (vpmdhaj _DAEMONIZED marker)

`UC_17_11` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process) as parent_cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","npm.exe","npm-cli.js","npx.exe") (Processes.process_name IN ("bun.exe","node.exe") OR Processes.process="*bun *" OR Processes.process="*opensearch_init.js*" OR Processes.process="*ai_init.js*" OR Processes.process="*payload.bin*" OR Processes.process="*preinstall.js*" OR Processes.process="*setup.mjs*" OR Processes.process="*_DAEMONIZED*") by host Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("node.exe","npm.exe","npx.exe","bun.exe")
     or InitiatingProcessCommandLine has_any ("npm-cli.js","npm install","npm i ")
| where FileName has_any ("node.exe","bun.exe")
     or ProcessCommandLine has_any ("opensearch_init.js","ai_init.js","payload.bin","preinstall.js","setup.mjs","_DAEMONIZED")
     or ProcessCommandLine matches regex @"(?i)bun\s+(run\s+)?\.\\?node_modules\\"
| where FolderPath has "node_modules" or InitiatingProcessFolderPath has "node_modules" or InitiatingProcessCommandLine has "node_modules" or ProcessCommandLine has "node_modules"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine, SHA256
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

### RMM tool installed by non-IT user — remote-access utility for hands-on-keyboard

`UC_RMM_TOOLS` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe","kaseya*.exe")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("AnyDesk.exe","TeamViewer.exe","TeamViewer_Service.exe",
        "ScreenConnect.ClientService.exe","ConnectWiseControl.ClientService.exe",
        "atera_agent.exe","SplashtopStreamer.exe","RustDesk.exe","NinjaOne.exe")
   or FileName matches regex @"(?i)kaseya.*\.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
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

### Article-specific behavioural hunt — Typosquatted npm Packages Steal Cloud and CI/CD Secrets From Developer Systems

`UC_17_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Typosquatted npm Packages Steal Cloud and CI/CD Secrets From Developer Systems ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("npm.js","node.js","preinstall.js","opensearch_init.js","ai_init.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("npm.js","node.js","preinstall.js","opensearch_init.js","ai_init.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Typosquatted npm Packages Steal Cloud and CI/CD Secrets From Developer Systems
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("npm.js", "node.js", "preinstall.js", "opensearch_init.js", "ai_init.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("npm.js", "node.js", "preinstall.js", "opensearch_init.js", "ai_init.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `aab.sportsontheweb.net`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `638788afc4f1b5860a328312caf5895abd5f5632d28a4f2a85b09076e270d15d`, `77d92efe7af3547f71fd41d4a884872d66b1be9499eaa637e91eac866911694d`, `bfa149694ec6411c23936311a999163ade54d6f38e2f4b0e3cfb8cb67bd7cfaa`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 12 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
