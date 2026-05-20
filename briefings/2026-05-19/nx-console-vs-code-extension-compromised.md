# [HIGH] Nx Console VS Code Extension Compromised

**Source:** StepSecurity
**Published:** 2026-05-19
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
- **T1543.001** — Create or Modify System Process: Launch Agent
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1547** — Boot or Logon Autostart Execution
- **T1102.002** — Web Service: Bidirectional Communication
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568** — Dynamic Resolution
- **T1552.005** — Unsecured Credentials: Cloud Instance Metadata API
- **T1528** — Steal Application Access Token
- **T1505.005** — Server Software Component: IDE Extensions

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Nx Console v18.95.0 — npx fetching nrwl/nx orphan commit 558b09d7

`UC_5_6` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name="npx" OR Processes.process_name="node" OR Processes.process="*npx*") (Processes.process="*github:nrwl/nx#558b09d7*" OR Processes.process="*nrwl/nx#558b09d*") by Processes.dest Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("npx","node")
| where ProcessCommandLine has "github:nrwl/nx#558b09d7"
   or ProcessCommandLine matches regex @"(?i)nrwl/nx#558b09d[0-9a-f]+"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### [LLM] kitty persistence — cat.py backdoor or com.user.kitty-monitor.plist LaunchAgent dropped

`UC_5_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as writer values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/Library/LaunchAgents/com.user.kitty-monitor.plist" OR Filesystem.file_path="*/.local/share/kitty/cat.py" OR Filesystem.file_name="com.user.kitty-monitor.plist" OR (Filesystem.file_name="cat.py" AND Filesystem.file_path="*/kitty/*")) by Filesystem.dest Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath endswith @"/Library/LaunchAgents/com.user.kitty-monitor.plist"
      or FolderPath endswith @"/.local/share/kitty/cat.py"
      or FileName =~ "com.user.kitty-monitor.plist"
      or (FileName =~ "cat.py" and FolderPath has "/kitty/"))
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] GitHub Search API C2 polling — query string 'firedalazer'

`UC_5_8` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.user) as user values(Web.src) as src values(Web.http_user_agent) as ua from datamodel=Web where Web.url="*api.github.com/search/commits*" Web.url="*firedalazer*" by Web.dest Web.url | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "api.github.com"
| where RemoteUrl has "search/commits" and RemoteUrl has "firedalazer"
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] AWS IMDS (169.254.169.254) accessed from non-AWS developer endpoint

`UC_5_9` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.process) as proc values(All_Traffic.user) as user values(All_Traffic.src) as src values(All_Traffic.src_category) as src_cat from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="169.254.169.254" NOT All_Traffic.src_category="aws_instance" NOT All_Traffic.src_category="ec2" by All_Traffic.dest All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where count > 0
```

**Defender KQL:**
```kql
let AwsHosts = DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, *) by DeviceId
    | where DeviceType =~ "Server" and (Vendor has_any ("Amazon","AWS") or AdditionalFields has "ec2")
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP == "169.254.169.254"
| where DeviceId !in (AwsHosts)
| where InitiatingProcessFileName !in~ ("aws","aws.exe","awscli","ec2-instance-connect","amazon-ssm-agent","ssm-agent","cloud-init","WindowsAzureGuestAgent.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] Nx Console v18.95.0 — malicious VSIX / main.js / payload hash on disk

`UC_5_10` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process_name) as proc values(Processes.process) as cmd values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.process_hash IN ("1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1") by Processes.dest Processes.process_hash | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1") by Filesystem.dest Filesystem.file_hash | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let IocHashes = dynamic([
    "1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8",
    "b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74",
    "e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1"
]);
union isfuzzy=true
  (DeviceFileEvents
    | where Timestamp > ago(90d)
    | where SHA256 in (IocHashes)
    | project Timestamp, Table="DeviceFileEvents", DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where SHA256 in (IocHashes) or InitiatingProcessSHA256 in (IocHashes)
    | project Timestamp, Table="DeviceProcessEvents", DeviceName, FileName=FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine),
  (DeviceImageLoadEvents
    | where Timestamp > ago(90d)
    | where SHA256 in (IocHashes)
    | project Timestamp, Table="DeviceImageLoadEvents", DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine="")
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

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 19 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
