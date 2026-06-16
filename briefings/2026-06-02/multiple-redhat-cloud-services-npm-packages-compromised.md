# [HIGH] Multiple redhat-cloud-services npm Packages compromised

**Source:** StepSecurity
**Published:** 2026-06-02
**Article:** https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised

## Threat Profile

Back to Blog Threat Intel Multiple redhat-cloud-services npm Packages compromised Several packages in the @redhat-cloud-services npm scope were found to carry malicious payloads that fire via a preinstall hook on every npm install. The affected versions span multiple packages across the RedHat Cloud Services frontend ecosystem. The payload is a sophisticated multi-stage credential harvester that targets GitHub Actions secrets, AWS, GCP, Azure, Kubernetes, HashiCorp Vault, npm tokens, and CircleC…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — JavaScript
- **T1105** — Ingress Tool Transfer
- **T1036.005** — Match Legitimate Name or Location
- **T1003.007** — Proc Filesystem
- **T1552.001** — Credentials In Files
- **T1212** — Exploitation for Credential Access
- **T1140** — Deobfuscate/Decode Files or Information
- **T1620** — Reflective Code Loading

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm preinstall hook executing oversized node index.js from @redhat-cloud-services package

`UC_158_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_path) as image values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("npm","npm.exe","npm-cli.js","node","node.exe","yarn","pnpm") Processes.process_name IN ("node","node.exe") (Processes.process="*@redhat-cloud-services*index.js*" OR Processes.process="*node_modules/@redhat-cloud-services/*index.js*") by Processes.dest Processes.user Processes.process_id Processes.parent_process Processes.process | `drop_dm_object_name(Processes)` | join type=left dest process [| tstats `summariesonly` values(Filesystem.file_size) as file_size from datamodel=Endpoint.Filesystem where Filesystem.file_path="*@redhat-cloud-services*index.js" by Filesystem.dest Filesystem.file_path | `drop_dm_object_name(Filesystem)` | where file_size > 1048576] | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let SuspectPackages = dynamic(["@redhat-cloud-services/types","@redhat-cloud-services/frontend-components-utilities","@redhat-cloud-services/frontend-components","@redhat-cloud-services/rbac-client","@redhat-cloud-services/javascript-clients-shared","@redhat-cloud-services/frontend-components-config-utilities","@redhat-cloud-services/frontend-components-notifications","@redhat-cloud-services/tsc-transform-imports","@redhat-cloud-services/frontend-components-config","@redhat-cloud-services/eslint-config-redhat-cloud-services","@redhat-cloud-services/host-inventory-client","@redhat-cloud-services/rule-components","@redhat-cloud-services/notifications-client","@redhat-cloud-services/chrome","@redhat-cloud-services/hcc-pf-mcp"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("npm","npm.exe","node","node.exe","yarn","pnpm","npx","npm-cli.js")
| where FileName in~ ("node","node.exe")
| where ProcessCommandLine has "@redhat-cloud-services" and ProcessCommandLine has "index.js"
| extend MatchedPackage = tostring(set_difference(SuspectPackages, dynamic([])))
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FolderPath has "@redhat-cloud-services" and FileName =~ "index.js"
    | where FileSize > 1048576
    | summarize MaxSize = max(FileSize) by DeviceId, FolderPath
) on DeviceId
| project Timestamp, DeviceName, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, MaxSize, MatchedPackage
| order by Timestamp desc
```

### Bun runtime download to /tmp from a node process during npm install

`UC_158_7` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.user) as user values(All_Traffic.app) as app from datamodel=Network_Traffic.All_Traffic where All_Traffic.app IN ("node","node.exe","npm") (All_Traffic.url="*github.com/oven-sh/bun/releases*" OR All_Traffic.url="*bun-v1.3.13*" OR All_Traffic.dest="objects.githubusercontent.com") by All_Traffic.src All_Traffic.process_id | `drop_dm_object_name(All_Traffic)` | join type=left src [| tstats `summariesonly` values(Filesystem.file_path) as bun_path from datamodel=Endpoint.Filesystem where Filesystem.file_path="/tmp/*" (Filesystem.file_name="bun" OR Filesystem.file_name="bun.exe") by Filesystem.dest | rename Filesystem.dest as src] | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
let BunDownload = DeviceNetworkEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessFileName in~ ("node","node.exe","npm")
    | where (RemoteUrl has "github.com/oven-sh/bun/releases" or RemoteUrl has "bun-v1.3.13" or RemoteUrl has "objects.githubusercontent.com")
    | project Timestamp, DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP;
let BunDrop = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where ActionType == "FileCreated"
    | where FolderPath startswith "/tmp/" or FolderPath startswith "/var/folders/"
    | where FileName in~ ("bun","bun.exe")
    | where InitiatingProcessFileName in~ ("node","node.exe","tar","unzip")
    | project Timestamp, DeviceId, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine;
BunDownload
| join kind=inner BunDrop on DeviceId
| where Timestamp1 between (Timestamp .. Timestamp + 5m)
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, DropPath = strcat(FolderPath, FileName), InitiatingProcessCommandLine
| order by Timestamp desc
```

### Process reading /proc/<pid>/mem of GitHub Actions Runner.Worker (in-memory secret extraction)

`UC_158_8` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as proc values(Filesystem.process_path) as proc_path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.action="read" Filesystem.file_path="/proc/*/mem" Filesystem.process_name IN ("node","bun") by Filesystem.dest Filesystem.file_path Filesystem.process_id | `drop_dm_object_name(Filesystem)` | rex field=file_path "/proc/(?<target_pid>\d+)/mem" | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileOpened","FileAccessed","FileCreated")
| where FolderPath startswith "/proc/" and FileName == "mem"
| where InitiatingProcessFileName in~ ("node","bun")
| extend TargetPid = extract(@"/proc/(\d+)/", 1, FolderPath)
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName has_any ("Runner.Worker","Runner.Listener")
    | project DeviceId, TargetPid = tostring(ProcessId), RunnerCmd = ProcessCommandLine, RunnerName = FileName
) on DeviceId, TargetPid
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, TargetPid, RunnerName, RunnerCmd
| order by Timestamp desc
```

### Bun spawned from npm install context executing /tmp/p*.js implant

`UC_158_9` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where (Processes.process_path="/tmp/*/bun" OR Processes.process_path="/tmp/*/bun.exe" OR Processes.process_name="bun") Processes.parent_process_name IN ("node","npm","node.exe") Processes.process="*/tmp/p*.js*" by Processes.dest Processes.user Processes.process_id Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (FolderPath startswith "/tmp/" and FileName in~ ("bun","bun.exe")) or (InitiatingProcessFolderPath startswith "/tmp/" and InitiatingProcessFileName in~ ("bun","bun.exe"))
| where InitiatingProcessFileName in~ ("node","node.exe","npm","bun")
| where ProcessCommandLine matches regex @"/tmp/p[A-Za-z0-9]+\.js"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Multiple redhat-cloud-services npm Packages compromised

`UC_158_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Multiple redhat-cloud-services npm Packages compromised ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Multiple redhat-cloud-services npm Packages compromised
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 10 use case(s) fired, 17 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
