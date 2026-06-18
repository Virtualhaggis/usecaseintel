# [HIGH] GitHub to Disable npm Install Scripts by Default to Stop Supply Chain Attacks

**Source:** The Hacker News
**Published:** 2026-06-11
**Article:** https://thehackernews.com/2026/06/github-to-disable-npm-install-scripts.html

## Threat Profile

GitHub to Disable npm Install Scripts by Default to Stop Supply Chain Attacks 
 Ravie Lakshmanan  Jun 11, 2026 Developer Security / Software Supply Chain 
GitHub has announced what it said are "breaking changes" coming to npm version 12, one of which turns off install scripts by default to combat software supply chain threats.
The changes aim to combat attack techniques that abuse the "npm install" command to trigger the execution of malicious code using npm lifecycle hooks. "Npm install" is u…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1059.003** — Windows Command Shell
- **T1059** — Command and Scripting Interpreter
- **T1574** — Hijack Execution Flow
- **T1562.001** — Disable or Modify Tools
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm/node spawning shell or LOLBin child during install lifecycle script

`UC_117_6` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("npm.exe","node.exe","npx.exe","npm-cli.js","yarn.exe","pnpm.exe")) AND (Processes.parent_process="*install*" OR Processes.parent_process="*ci *" OR Processes.parent_process="*rebuild*" OR Processes.parent_process="*postinstall*" OR Processes.parent_process="*preinstall*" OR Processes.parent_process="*prepare*") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","curl.exe","wget.exe","bitsadmin.exe","certutil.exe","sh.exe","bash.exe") by host, user, Processes.parent_process_name, Processes.process_name | `drop_dm_object_name(Processes)` | where NOT match(child_cmdline, "(?i)node_modules.\\(husky|lint-staged|webpack|gulp|electron-builder|playwright|esbuild)")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe")
| where InitiatingProcessCommandLine has_any ("install"," ci ","rebuild","postinstall","preinstall","prepare")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","curl.exe","wget.exe","bitsadmin.exe","certutil.exe","sh.exe","bash.exe")
| where AccountName !endswith "$"
| where not (ProcessCommandLine has_any ("husky","lint-staged","webpack","electron-builder","playwright install"))
| extend WriteOrDownload = iff(ProcessCommandLine has_any ("curl ","wget ","Invoke-WebRequest","DownloadString","DownloadFile","bitsadmin /transfer","certutil -urlcache","iwr ","iex "), "yes", "no")
| project Timestamp, DeviceName, AccountName, ParentCmd = InitiatingProcessCommandLine, ChildImage = FolderPath, ChildCmd = ProcessCommandLine, WriteOrDownload, SHA256
| order by Timestamp desc
```

### node-gyp implicit rebuild spawning unexpected children via binding.gyp

`UC_117_7` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as child_cmdline values(Processes.parent_process) as parent_cmdline from datamodel=Endpoint.Processes where (Processes.parent_process="*node-gyp*" OR Processes.parent_process="*binding.gyp*" OR Processes.parent_process="*gyp.py*") AND Processes.process_name IN ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","curl.exe","wget.exe","bitsadmin.exe","certutil.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe") by host, user, Processes.parent_process_name, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessCommandLine has_any ("node-gyp","binding.gyp","gyp.py","gyp_main.py")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","mshta.exe","curl.exe","wget.exe","bitsadmin.exe","certutil.exe","rundll32.exe","regsvr32.exe","wscript.exe","cscript.exe","sh.exe","bash.exe")
| where AccountName !endswith "$"
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "npm.exe" or FileName =~ "node.exe"
    | where ProcessCommandLine has_any ("install"," ci ","rebuild")
    | project AncestorTime = Timestamp, DeviceId, AncestorCmd = ProcessCommandLine
  ) on DeviceId
| where Timestamp between (AncestorTime .. AncestorTime + 10m)
| project Timestamp, DeviceName, AccountName, AncestorCmd, GypParent = InitiatingProcessCommandLine, Child = FileName, ChildCmd = ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### npm install spawning git from non-standard path (.npmrc Git executable override)

`UC_117_8` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as child_path from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe") AND Processes.process_name="git.exe" by host, user, Processes.parent_process, Processes.process_path | `drop_dm_object_name(Processes)` | where NOT match(child_path, "(?i)^(C:\\\\Program Files\\\\Git\\\\|C:\\\\Program Files \\(x86\\)\\\\Git\\\\|C:\\\\Windows\\\\System32\\\\|C:\\\\Users\\\\[^\\\\]+\\\\AppData\\\\Local\\\\Programs\\\\Git\\\\)")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe")
| where FileName =~ "git.exe"
| where not (FolderPath startswith @"C:\Program Files\Git\")
| where not (FolderPath startswith @"C:\Program Files (x86)\Git\")
| where not (FolderPath startswith @"C:\Windows\System32\")
| where not (FolderPath matches regex @"(?i)^C:\\Users\\[^\\]+\\AppData\\Local\\Programs\\Git\\")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, GitPath = FolderPath, GitCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### npm/node fetching dependency from non-registry HTTPS or Git URL

`UC_117_9` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as port from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe") AND All_Traffic.dest_port IN (443,80) by host, user, All_Traffic.app, All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | where NOT match(dest, "(?i)(registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com|npm\.pkg\.github\.com|pkgs\.dev\.azure\.com|.+\.jfrog\.io|.+\.cloudsmith\.io|.+\.nexus\.repo\.local)$")
```

**Defender KQL:**
```kql
let RegistryAllowlist = dynamic(["registry.npmjs.org","registry.yarnpkg.com","registry.npmmirror.com","npm.pkg.github.com","pkgs.dev.azure.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe")
| where RemoteIPType == "Public"
| where InitiatingProcessCommandLine has_any ("install"," ci ","add ","fetch")
| where isnotempty(RemoteUrl)
| extend Host = tolower(tostring(parse_url(RemoteUrl).Host))
| where not (Host in (RegistryAllowlist))
| where not (Host endswith ".jfrog.io" or Host endswith ".cloudsmith.io" or Host endswith ".nexus.local")
| extend IsGitOrTarball = iff(RemoteUrl has_any (".git",".tar.gz",".tgz",".tar.xz","/tarball/","/archive/"), "yes", "no")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, IsGitOrTarball
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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

### Article-specific behavioural hunt — GitHub to Disable npm Install Scripts by Default to Stop Supply Chain Attacks

`UC_117_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — GitHub to Disable npm Install Scripts by Default to Stop Supply Chain Attacks ```
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
// Article-specific bespoke detection — GitHub to Disable npm Install Scripts by Default to Stop Supply Chain Attacks
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


## Why this matters

Severity classified as **HIGH** based on: 10 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
