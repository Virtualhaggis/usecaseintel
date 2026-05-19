# [HIGH] Nx Console VS Code Extension Compromised

**Source:** StepSecurity
**Published:** 2026-05-18
**Article:** https://www.stepsecurity.io/blog/nx-console-vs-code-extension-compromised

## Threat Profile

Back to Blog Threat Intel Nx Console VS Code Extension Compromised Version 18.95.0 of the popular Nx Console extension (2.2M+ installs) was published with malicious code targeting developer credentials, cloud infrastructure tokens, and CI/CD secrets. Here's what we know so far. Ashish Kurmi View LinkedIn May 18, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
This is a developing story. We will update this post with additional…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`
- **SHA256:** `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74`
- **SHA256:** `e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1`

## MITRE ATT&CK Techniques

- **T1071.001** — Web Protocols
- **T1071.004** — DNS
- **T1048.003** — Exfiltration Over Unencrypted Non-C2 Protocol
- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1543.001** — Persistence (article-specific)
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1105** — Ingress Tool Transfer
- **T1547.011** — Boot or Logon Autostart Execution: Plist File Modification
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102.002** — Web Service: Bidirectional Communication
- **T1568** — Dynamic Resolution
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Nx Console backdoor — malicious npx fetch of nrwl/nx orphan commit 558b09d7

`UC_5_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) AS firstTime max(_time) AS lastTime FROM datamodel=Endpoint.Processes WHERE (Processes.process_name IN ("npx.cmd","npx.exe","node.exe","npm.cmd","npm.exe","npx","node")) Processes.process="*github:nrwl/nx*" Processes.process="*558b09d7*" BY Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npx.cmd","npx.exe","node.exe","npm.cmd","npm.exe","npx","node")
| where ProcessCommandLine has "github:nrwl/nx"
| where ProcessCommandLine has "558b09d7"
| extend EditorParent = iif(InitiatingProcessFileName has_any ("Code.exe","Code - Insiders.exe","Cursor.exe","Electron","code","cursor") or InitiatingProcessParentFileName has_any ("Code.exe","Code - Insiders.exe","Cursor.exe"), "VSCodeFamily", "Other")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessParentFileName, EditorParent, SHA256
| order by Timestamp desc
```

### [LLM] Nx Console backdoor — known-malicious VSIX / main.js / payload SHA256 on disk

`UC_5_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) AS firstTime max(_time) AS lastTime FROM datamodel=Endpoint.Filesystem WHERE Filesystem.file_hash IN ("1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1") BY Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
let MaliciousHashes = dynamic([
    "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8",
    "b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74",
    "e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1"]);
union isfuzzy=true
  (DeviceFileEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (MaliciousHashes)
   | project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
  (DeviceProcessEvents
   | where Timestamp > ago(30d)
   | where SHA256 in (MaliciousHashes) or InitiatingProcessSHA256 in (MaliciousHashes)
   | project Timestamp, DeviceName, ActionType="ProcessExecuted", FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=AccountName),
  (AlertEvidence
   | where Timestamp > ago(30d)
   | where SHA256 in (MaliciousHashes)
   | project Timestamp, DeviceName, ActionType="AlertEvidence", FileName, FolderPath, SHA256, InitiatingProcessFileName="", InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessAccountName=AccountName)
| order by Timestamp desc
```

### [LLM] Nx Console backdoor — macOS LaunchAgent + kitty persistence artefact creation

`UC_5_8` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) AS firstTime max(_time) AS lastTime FROM datamodel=Endpoint.Filesystem WHERE (Filesystem.file_path="*/Library/LaunchAgents/com.user.kitty-monitor.plist" OR Filesystem.file_path="*/.local/share/kitty/cat.py" OR Filesystem.file_path="*/tmp/kitty-*") BY Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.process | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath has "/Library/LaunchAgents" and FileName =~ "com.user.kitty-monitor.plist")
    or (FolderPath has "/.local/share/kitty" and FileName =~ "cat.py")
    or (FolderPath matches regex @"(?i)/tmp/kitty-[a-z0-9]+")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] Nx Console backdoor — GitHub commit-search C2 polling for 'firedalazer' marker

`UC_5_9` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) AS firstTime max(_time) AS lastTime FROM datamodel=Web.Web WHERE Web.url="*api.github.com*" Web.url="*firedalazer*" BY Web.dest Web.src Web.user Web.url Web.http_user_agent | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
union isfuzzy=true
  (DeviceNetworkEvents
   | where Timestamp > ago(7d)
   | where RemoteUrl has "api.github.com"
   | where RemoteUrl has "firedalazer"
   | project Timestamp, DeviceName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
  (DeviceProcessEvents
   | where Timestamp > ago(7d)
   | where ProcessCommandLine has "firedalazer" and ProcessCommandLine has "api.github.com"
   | project Timestamp, DeviceName, RemoteIP="", RemoteUrl="", RemotePort=int(null), InitiatingProcessFileName=FileName, InitiatingProcessCommandLine=ProcessCommandLine, InitiatingProcessAccountName=AccountName)
| order by Timestamp desc
```

### [LLM] Nx Console backdoor — AWS IMDS access (169.254.169.254) from developer workstation

`UC_5_10` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) AS firstTime max(_time) AS lastTime FROM datamodel=Network_Traffic.All_Traffic WHERE All_Traffic.dest="169.254.169.254" All_Traffic.dest_port IN (80,443) BY All_Traffic.src All_Traffic.user All_Traffic.dest All_Traffic.dest_port All_Traffic.app All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | where NOT match(app,"(?i)cloud-init|aws-cli|ec2-net-utils|kube-proxy|amazon-ssm-agent")
```

**Defender KQL:**
```kql
let WorkstationOS = dynamic(["Windows10","Windows11","MacOS","macOS"]);
let Workstations = DeviceInfo
    | where Timestamp > ago(1d)
    | where OSPlatform in (WorkstationOS)
    | summarize arg_max(Timestamp, DeviceId, OSPlatform) by DeviceName
    | project DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "169.254.169.254"
| where RemotePort in (80, 443)
| where ActionType in ("ConnectionSuccess","ConnectionAttempt")
| where DeviceId in (Workstations)
| where InitiatingProcessFileName !in~ ("AWSCLI.exe","aws.exe","aws-vault.exe","saml2aws.exe","kube-proxy","amazon-ssm-agent")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName, InitiatingProcessParentFileName
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

### DNS tunneling / TXT-heavy domain queries

`UC_DNS_TUNNEL` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Network_Resolution.DNS
    where DNS.message_type="QUERY"
    by DNS.src, DNS.query
| `drop_dm_object_name(DNS)`
| eval qlen=len(query)
| where qlen > 50
| rex field=query "(?<second_level_domain>[\w-]+\.[\w-]+)$"
| stats sum(count) AS qcount, dc(query) AS unique_subs, max(qlen) AS max_label
    by src, second_level_domain
| where qcount > 100 AND unique_subs > 20
| sort - qcount
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort == 53 and isnotempty(RemoteUrl)
| extend qlen = strlen(RemoteUrl)
| where qlen > 50
| extend SecondLevelDomain = extract(@"([\w-]+\.[a-zA-Z]{2,})$", 1, RemoteUrl)
| summarize qcount = count(), uniqueSubs = dcount(RemoteUrl), maxLabel = max(qlen)
    by DeviceName, SecondLevelDomain
| where qcount > 100 and uniqueSubs > 20
| order by qcount desc
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

### Article-specific behavioural hunt — Nx Console VS Code Extension Compromised

`UC_5_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Nx Console VS Code Extension Compromised ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("main.js","cat.py","index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/Library/LaunchAgents/com.user.kitty-monitor.plist*" OR Filesystem.file_path="*/tmp/kitty-*" OR Filesystem.file_name IN ("main.js","cat.py","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Nx Console VS Code Extension Compromised
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("main.js", "cat.py", "index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/Library/LaunchAgents/com.user.kitty-monitor.plist", "/tmp/kitty-") or FileName in~ ("main.js", "cat.py", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`, `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74`, `e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
