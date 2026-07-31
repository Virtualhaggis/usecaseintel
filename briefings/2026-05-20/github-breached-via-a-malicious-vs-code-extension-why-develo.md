# [HIGH] GitHub breached via a malicious VS Code extension: why developer devices are the real target

**Source:** Aikido
**Published:** 2026-05-20
**Article:** https://www.aikido.dev/blog/github-breached-vs-code-extension

## Threat Profile

Blog Vulnerabilities & Threats GitHub breached via a malicious VS Code extension: why developer devices are the real target GitHub breached via a malicious VS Code extension: why developer devices are the real target Written by Shaun Brown Published on: May 20, 2026 On May 19, GitHub disclosed that it was investigating unauthorized access to internal repositories. TeamPCP claims to have extracted data from roughly 4,000 private repos. The reported vector: a malicious VS Code extension installed …

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `check.git-service.com`
- **SHA256:** `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`
- **SHA256:** `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74`
- **SHA256:** `e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1`
- **SHA256:** `43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1071.004** — Application Layer Protocol: DNS
- **T1567** — Exfiltration Over Web Service
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1176** — Browser Extensions
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1555** — Credentials from Password Stores
- **T1083** — File and Directory Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### DNS / Network egress to TeamPCP Nx Console C2 domain check.git-service.com

`UC_417_4` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.dest) as dest from datamodel=Network_Resolution where DNS.query="check.git-service.com" OR DNS.query="*.git-service.com" by DNS.query host | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [ | tstats `summariesonly` count from datamodel=Web where Web.url="*git-service.com*" by Web.src Web.url Web.user_agent | `drop_dm_object_name(Web)` ]
```

**Defender KQL:**
```kql
union
(DeviceNetworkEvents
 | where Timestamp > ago(30d)
 | where RemoteUrl has "git-service.com" or RemoteIP in ("")
 | extend Source="NetworkEvent"
 | project Timestamp, DeviceName, Source, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort),
(DeviceEvents
 | where Timestamp > ago(30d)
 | where ActionType == "DnsQueryResponse" or ActionType == "InboundConnectionAccepted" or ActionType == "ConnectionSuccess"
 | where RemoteUrl has "git-service.com" or AdditionalFields has "git-service.com"
 | extend Source="DeviceEvent"
 | project Timestamp, DeviceName, Source, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort)
| order by Timestamp desc
```

### TeamPCP Nx Console payload SHA256 hash match on developer endpoints

`UC_417_5` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.file_hash IN ("1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1","43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9") by Filesystem.dest Filesystem.file_hash Filesystem.user | `drop_dm_object_name(Filesystem)` | append [ | tstats `summariesonly` count from datamodel=Endpoint.Processes where Processes.process_hash IN ("1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1","43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9") by Processes.dest Processes.process Processes.user Processes.process_hash | `drop_dm_object_name(Processes)` ]
```

**Defender KQL:**
```kql
let TeamPCPHashes = dynamic(["1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1","43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9"]);
union
(DeviceFileEvents
 | where Timestamp > ago(90d)
 | where SHA256 in (TeamPCPHashes)
 | extend EventSource="DeviceFileEvents"
 | project Timestamp, DeviceName, EventSource, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName),
(DeviceProcessEvents
 | where Timestamp > ago(90d)
 | where SHA256 in (TeamPCPHashes) or InitiatingProcessSHA256 in (TeamPCPHashes)
 | extend EventSource="DeviceProcessEvents"
 | project Timestamp, DeviceName, EventSource, ActionType="ProcessCreated", FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=AccountName),
(DeviceImageLoadEvents
 | where Timestamp > ago(90d)
 | where SHA256 in (TeamPCPHashes)
 | extend EventSource="DeviceImageLoadEvents"
 | project Timestamp, DeviceName, EventSource, ActionType="ImageLoaded", FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName=InitiatingProcessAccountName)
| order by Timestamp desc
```

### VS Code child process fetching payload from nrwl/nx orphan commit (Nx Console v18.95.0 dropper)

`UC_417_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as pcmd from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("Code.exe","Code - Insiders.exe","code","Code Helper","Code Helper (Plugin)") OR match(Processes.parent_process,"(?i)\\\\Code(?:\\s-\\sInsiders)?\\.exe")) (Processes.process_name IN ("npx.cmd","npx","node.exe","node","cmd.exe","powershell.exe","pwsh.exe","bash","sh") AND (Processes.process="*558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2*" OR Processes.process="*raw.githubusercontent.com/nrwl/nx*" OR Processes.process="*github.com/nrwl/nx/raw*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("Code.exe","Code - Insiders.exe","code","Code Helper","Code Helper (Plugin)","Code Helper (Renderer)")
   or InitiatingProcessParentFileName in~ ("Code.exe","Code - Insiders.exe","code")
| where FileName in~ ("npx.cmd","npx","node.exe","node","cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe")
| where ProcessCommandLine has_any ("558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2","raw.githubusercontent.com/nrwl/nx","github.com/nrwl/nx/raw","codeload.github.com/nrwl/nx")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, FileName, ProcessCommandLine, SHA256, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Burst credential-file harvest by VS Code / node process (Nx Console stealer behaviour)

`UC_417_7` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as touched_files dc(Filesystem.file_path) as distinct_paths from datamodel=Endpoint.Filesystem where Filesystem.process_name IN ("node.exe","node","Code.exe","Code - Insiders.exe","Code Helper") AND (Filesystem.file_path="*\\.env*" OR Filesystem.file_name=".env" OR Filesystem.file_name=".envrc" OR Filesystem.file_path="*\\.aws\\credentials*" OR Filesystem.file_path="*/.aws/credentials*" OR Filesystem.file_name=".npmrc" OR Filesystem.file_path="*\\.kube\\config*" OR Filesystem.file_path="*/.kube/config*" OR Filesystem.file_path="*\\.claude\\settings.json*" OR Filesystem.file_path="*/.claude/settings.json*" OR Filesystem.file_path="*\\.config\\1Password*" OR Filesystem.file_path="*/.config/1Password*" OR Filesystem.file_path="*\\.docker\\config.json*" OR Filesystem.file_name="vault-token") by Filesystem.dest Filesystem.user Filesystem.process_id Filesystem.process_name _time span=5m | `drop_dm_object_name(Filesystem)` | where distinct_paths >= 5
```

**Defender KQL:**
```kql
let CredPathFragments = dynamic([@"\.aws\credentials", @"/.aws/credentials", @"\.npmrc", @"/.npmrc", @"\.kube\config", @"/.kube/config", @"\.claude\settings.json", @"/.claude/settings.json", @"\.config\1Password", @"/.config/1Password", @"\.docker\config.json", @"vault-token", @".gitconfig"]);
let CredFileNames = dynamic([".env",".envrc","credentials",".npmrc",".pypirc","settings.json","config","vault-token"]);
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node","Code.exe","Code - Insiders.exe","Code Helper","Code Helper.exe")
| where (FolderPath has_any (CredPathFragments)) or (FileName in~ (CredFileNames) and FolderPath !contains "node_modules")
| summarize DistinctPaths = dcount(strcat(FolderPath, FileName)), SamplePaths = make_set(strcat(FolderPath, FileName), 25), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Cmd = any(InitiatingProcessCommandLine)
  by DeviceName, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessAccountName, bin(Timestamp, 5m)
| where DistinctPaths >= 5
| order by FirstSeen desc
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

### Article-specific behavioural hunt — GitHub breached via a malicious VS Code extension: why developer devices are the

`UC_417_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — GitHub breached via a malicious VS Code extension: why developer devices are the ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("timeago.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("timeago.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — GitHub breached via a malicious VS Code extension: why developer devices are the
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("timeago.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("timeago.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `check.git-service.com`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`, `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74`, `e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1`, `43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 8 use case(s) fired, 16 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
