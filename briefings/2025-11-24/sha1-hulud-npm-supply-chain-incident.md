# [HIGH] SHA1-Hulud, npm supply chain incident

**Source:** Snyk
**Published:** 2025-11-24
**Article:** https://snyk.io/blog/sha1-hulud-npm-supply-chain-incident/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
November 24, 2025
0 mins read On November 24th, 2025, we identified a new supply chain attack in the npm ecosystem, referred to as SHA1-Hulud. We believe this is a second wave of the Shai-Hulud attack, which occurred in September 2025. 
Snyk will continue monitoring this active incident until it is resolved. Updates on this incident will be on our trust center .
What is it? The SHA1-Hulud vulnerability is a worm that has the ability to infiltra…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `webhook.site`
- **SHA256:** `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
- **SHA256:** `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`
- **SHA256:** `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`
- **SHA256:** `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`
- **SHA256:** `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`
- **SHA256:** `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`
- **SHA256:** `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`
- **SHA256:** `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`
- **SHA1:** `d60ec97eea19fffb4809bc35b91033b52490ca11`
- **SHA1:** `3d7570d14d34b0ba137d502f042b27b0f37a59fa`
- **SHA1:** `d1829b4708126dcc7bea7437c04d1f10eacd4a16`

## MITRE ATT&CK Techniques

- **T1566.002** — Spearphishing Link
- **T1204.001** — User Execution: Malicious Link
- **T1059.001** — PowerShell
- **T1204.004** — User Execution: Malicious Copy and Paste
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1059.007** — JavaScript
- **T1546.016** — Installer Packages
- **T1552.001** — Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1083** — File and Directory Discovery
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Web Protocols
- **T1102** — Web Service
- **T1552.005** — Cloud Instance Metadata API
- **T1078.004** — Cloud Accounts
- **T1547** — Boot or Logon Autostart Execution
- **T1053.005** — Scheduled Task/Job: Scheduled Task (CI workflow analogue)
- **T1485** — Data Destruction
- **T1561.002** — Disk Structure Wipe (logical)

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] SHA1-Hulud worm payload execution via npm preinstall (setup_bun.js / bun_environment.js)

`UC_657_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("npm.exe","npm-cli.js","node.exe","npm","node","yarn","pnpm") (Processes.process IN ("*setup_bun.js*","*bun_environment.js*") OR Processes.process_name IN ("bun.exe","bun") AND Processes.process IN ("*bun_environment.js*","*setup_bun.js*")) by host Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npm","node","yarn","pnpm")
         or InitiatingProcessCommandLine has_any ("npm install","npm ci","yarn install","pnpm install","preinstall"))
| where ProcessCommandLine has_any ("setup_bun.js","bun_environment.js")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] TruffleHog secret-scanner execution on developer / CI host (SHA1-Hulud credential harvest)

`UC_657_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process_name IN ("trufflehog","trufflehog.exe","trufflehog3") OR Processes.process IN ("*trufflehog*git*","*trufflehog filesystem*","*trufflehog github*")) by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | search NOT user IN ("*secops*","*appsec*") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName has "trufflehog"
   or ProcessCommandLine has_any ("trufflehog filesystem","trufflehog git ","trufflehog github","trufflehog --json")
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","bun.exe","sh","bash","zsh","powershell.exe","pwsh.exe","cmd.exe","yarn.exe","pnpm.exe")
| project Timestamp, DeviceName, AccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Outbound exfiltration to webhook.site from npm / node / bun process tree

`UC_657_7` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as port from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name IN ("node.exe","npm.exe","bun.exe","yarn.exe","pnpm.exe","node","npm","bun") (All_Traffic.dest="webhook.site" OR All_Traffic.url="*webhook.site*" OR All_Traffic.dest_host="webhook.site") by host All_Traffic.user All_Traffic.process_name All_Traffic.url | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","bun.exe","yarn.exe","pnpm.exe","node","npm","bun","curl.exe","wget.exe")
| where RemoteUrl has "webhook.site" or RemoteUrl matches regex @"webhook\.site\/[a-f0-9-]{8,}"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### [LLM] Cloud metadata service (IMDS) access from npm / node child process

`UC_657_8` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name IN ("node.exe","npm.exe","bun.exe","yarn.exe","pnpm.exe","node","npm","bun","curl.exe","wget.exe") (All_Traffic.dest IN ("169.254.169.254","100.100.100.200","fd00:ec2::254") OR All_Traffic.url IN ("*metadata.google.internal*","*169.254.169.254*","*metadata.azure.com*")) by host All_Traffic.user All_Traffic.process_name All_Traffic.url All_Traffic.dest | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","bun.exe","yarn.exe","pnpm.exe","node","npm","bun","curl.exe","wget.exe")
| where RemoteIP in ("169.254.169.254","100.100.100.200","fd00:ec2::254")
   or RemoteUrl has_any ("metadata.google.internal","169.254.169.254","metadata.azure.com")
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has_any ("setup_bun.js","bun_environment.js","preinstall","npm install","npm ci")
    | project DeviceId, InitiatingProcessId=ProcessId, MaliciousParentCmd=ProcessCommandLine
  ) on DeviceId, InitiatingProcessId
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteIP, RemoteUrl, MaliciousParentCmd
| order by Timestamp desc
```

### [LLM] Malicious '.github/workflows/discussion.yaml' workflow file created by npm/node

`UC_657_9` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as procs from datamodel=Endpoint.Filesystem where Filesystem.action=created (Filesystem.file_path="*\\.github\\workflows\\discussion.yaml" OR Filesystem.file_path="*/.github/workflows/discussion.yaml" OR Filesystem.file_path="*\\.github\\workflows\\discussion.yml" OR Filesystem.file_path="*/.github/workflows/discussion.yml") by host Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has @"\.github\workflows\" or FolderPath has @"/.github/workflows/")
| where FileName in~ ("discussion.yaml","discussion.yml")
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","bun.exe","yarn.exe","pnpm.exe","node","npm","bun")
   or InitiatingProcessCommandLine has_any ("setup_bun.js","bun_environment.js")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] SHA1-Hulud wiper: mass deletion of user home directory by npm/node descendant

`UC_657_10` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as deletes values(Filesystem.file_path) as paths min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("deleted","removed") (Filesystem.file_path="C:\\Users\\*" OR Filesystem.file_path="/home/*" OR Filesystem.file_path="/Users/*" OR Filesystem.file_path="/root/*") Filesystem.process_name IN ("node.exe","npm.exe","bun.exe","node","npm","bun","rm","sh","bash","powershell.exe","pwsh.exe") by host Filesystem.user Filesystem.process_name span=5m | `drop_dm_object_name(Filesystem)` | where deletes > 200 | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType == "FileDeleted"
| where FolderPath startswith @"C:\Users\" or FolderPath startswith "/home/" or FolderPath startswith "/Users/" or FolderPath startswith "/root/"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","bun.exe","node","npm","bun","rm","sh","bash","zsh","powershell.exe","pwsh.exe")
| summarize DeleteCount = count(),
            SamplePaths = make_set(FolderPath, 10),
            FirstDelete = min(Timestamp),
            LastDelete = max(Timestamp),
            DistinctTopLevelDirs = dcount(tostring(split(FolderPath, @"\")[2]))
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, bin(Timestamp, 5m)
| where DeleteCount > 200
| order by FirstDelete desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `webhook.site`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`, `62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0`, `f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068`, `cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd`, `a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a`, `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`, `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`, `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db` _(+3 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 21 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
