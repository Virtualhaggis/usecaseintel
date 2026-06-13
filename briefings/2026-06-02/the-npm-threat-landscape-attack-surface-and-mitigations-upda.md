# [CRIT] The npm Threat Landscape: Attack Surface and Mitigations (Updated June 2)

**Source:** Unit 42 (Palo Alto), StepSecurity
**Published:** 2026-06-02
**Article:** https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/

## Threat Profile

Threat Research Center 
High Profile Threats 
Malware 
Malware 
The npm Threat Landscape: Attack Surface and Mitigations 
12 min read 
Related Products Advanced DNS Security Advanced URL Filtering Cloud-Delivered Security Services Cortex Cortex Cloud Unit 42 Incident Response 
By: Unit 42 
Published: April 24, 2026 
Categories: High Profile Threats 
Malware 
Tags: Credential Harvesting 
GitHub 
Npm packages 
Obfuscation 
Payload 
Supply chain 
Worm propagation 
Executive Summary 
The security of…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `94.154.172.43`
- **Domain (defanged):** `audit.checkmarx.cx`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1071** — Application Layer Protocol
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1041** — Exfiltration Over C2 Channel
- **T1568** — Dynamic Resolution
- **T1546.016** — Event Triggered Execution: Installer Packages

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm/node lifecycle script fetching Bun runtime from github.com/oven-sh/bun

`UC_141_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parentcmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("npm.exe","npm-cli.js","node.exe","yarn.exe","pnpm.exe") AND Processes.process_name IN ("node.exe","curl.exe","powershell.exe","wget.exe","bun.exe","bash.exe","sh.exe")) (Processes.process="*github.com/oven-sh/bun*" OR Processes.process="*oven-sh/bun/releases*" OR Processes.process="*bun-windows-x64*" OR Processes.process="*bun-linux-x64*" OR Processes.process="*bun-darwin*") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | rename firstTime as _time | convert ctime(_time) ctime(lastTime)
```

**Defender KQL:**
```kql
let bunUrlIndicators = dynamic(["github.com/oven-sh/bun", "oven-sh/bun/releases", "bun-windows-x64", "bun-linux-x64", "bun-darwin"]);
let npmParents = dynamic(["npm.exe","npm-cli.js","node.exe","yarn.exe","pnpm.exe","npx.exe"]);
let downloaderChildren = dynamic(["node.exe","curl.exe","powershell.exe","wget.exe","bun.exe","bash.exe","sh.exe","pwsh.exe"]);
// Process-tree pivot — npm parent spawning a downloader child with Bun URL on the command line
let ProcHits = DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFileName in~ (npmParents) or InitiatingProcessParentFileName in~ (npmParents)
    | where FileName in~ (downloaderChildren)
    | where ProcessCommandLine has_any (bunUrlIndicators) or InitiatingProcessCommandLine has_any (bunUrlIndicators)
    | where AccountName !endswith "$"
    | project Timestamp, DeviceName, AccountName,
              ParentImage = InitiatingProcessParentFileName,
              InitImage  = InitiatingProcessFileName,
              InitCmd    = InitiatingProcessCommandLine,
              ChildImage = FileName,
              ChildCmd   = ProcessCommandLine, SHA256;
// Network pivot — same process families connecting to github.com for the Bun release tarball
let NetHits = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where RemoteUrl has "github.com" and (RemoteUrl has "oven-sh/bun" or RemoteUrl has "bun-windows" or RemoteUrl has "bun-linux" or RemoteUrl has "bun-darwin")
    | where InitiatingProcessFileName in~ (downloaderChildren)
    | where InitiatingProcessParentFileName in~ (npmParents) or InitiatingProcessCommandLine has_any (npmParents)
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              ParentImage = InitiatingProcessParentFileName,
              InitImage   = InitiatingProcessFileName,
              InitCmd     = InitiatingProcessCommandLine,
              ChildImage  = "<network-egress>", ChildCmd = RemoteUrl, SHA256 = InitiatingProcessSHA256;
union ProcHits, NetHits
| order by Timestamp desc
```

### C2 beacon to audit.checkmarx[.]cx /v1/telemetry (TeamPCP Shai-Hulud Third Coming)

`UC_141_9` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
(`cim_Network_Traffic_indexes` (dest="audit.checkmarx.cx" OR dest="audit.checkmarx[.]cx" OR dest_ip="94.154.172.43")) OR (`cim_Network_Resolution_indexes` query="*audit.checkmarx.cx*") OR (`cim_Web_indexes` (url="*audit.checkmarx.cx*" OR dest="audit.checkmarx.cx") (url="*/v1/telemetry*" OR uri_path="/v1/telemetry")) | stats min(_time) as firstTime max(_time) as lastTime count by host src dest dest_ip url http_method app | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let c2Hosts = dynamic(["audit.checkmarx.cx", "audit.checkmarx[.]cx"]);
let c2Ips    = dynamic(["94.154.172.43"]);
let c2Path   = "/v1/telemetry";
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where (RemoteUrl has_any (c2Hosts)) or (RemoteIP in (c2Ips)) or (RemoteUrl has c2Path and RemotePort in (443, 80))
| where InitiatingProcessFileName !in~ ("MsSense.exe","SenseIR.exe")
| project Timestamp, DeviceName,
          AccountName = InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort, Protocol
| order by Timestamp desc
```

### Malicious @bitwarden/cli payload artifacts on disk (bw_setup.js, bw1.js, Shai-Hulud markers)

`UC_141_10` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("bw_setup.js","bw1.js") OR Filesystem.file_path="*@bitwarden/cli*" OR Filesystem.file_path="*node_modules*@bitwarden*cli*") by host Filesystem.user Filesystem.process_name Filesystem.file_name | `drop_dm_object_name(Filesystem)` | appendpipe [| tstats summariesonly=t count from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe") Processes.process="*bw_setup.js*" OR Processes.process="*bw1.js*") by host Processes.user Processes.parent_process Processes.process | `drop_dm_object_name(Processes)`] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let stageFiles = dynamic(["bw_setup.js", "bw1.js"]);
let packageHints = dynamic(["@bitwarden\\cli", "@bitwarden/cli", "node_modules\\@bitwarden\\cli", "node_modules/@bitwarden/cli"]);
let shaiHuludMarker = "Shai-Hulud: The Third Coming";
let FileHits = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where (FileName in~ (stageFiles)) or (FolderPath has_any (packageHints) and FileName endswith ".js") or (AdditionalFields has shaiHuludMarker)
    | project Timestamp, DeviceName,
              AccountName = InitiatingProcessAccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName,
              FolderPath, FileName, SHA256;
let ProcHits = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npm-cli.js","bun.exe")
    | where ProcessCommandLine has_any (stageFiles)
    | project Timestamp, DeviceName, AccountName,
              InitiatingProcessFileName, InitiatingProcessCommandLine,
              InitiatingProcessParentFileName,
              FolderPath, FileName = FileName, SHA256, ProcCmd = ProcessCommandLine;
union FileHits, ProcHits
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

### Article-specific behavioural hunt — The npm Threat Landscape: Attack Surface and Mitigations (Updated June 2)

`UC_141_7` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The npm Threat Landscape: Attack Surface and Mitigations (Updated June 2) ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("mcpaddon.js","bw_setup.js","node.js","bw1.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_name IN ("mcpaddon.js","bw_setup.js","node.js","bw1.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The npm Threat Landscape: Attack Surface and Mitigations (Updated June 2)
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("mcpaddon.js", "bw_setup.js", "node.js", "bw1.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env") or FileName in~ ("mcpaddon.js", "bw_setup.js", "node.js", "bw1.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `94.154.172.43`, `audit.checkmarx.cx`


## Why this matters

Severity classified as **CRIT** based on: IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
