# [HIGH] GitHub Internal Repositories Breached via Malicious Nx Console VS Code Extension

**Source:** The Hacker News, BleepingComputer, Cyber Security News, Aikido
**Published:** 2026-05-21
**Article:** https://thehackernews.com/2026/05/github-internal-repositories-breached.html

## Threat Profile

Blog Vulnerabilities & Threats GitHub breached via a malicious VS Code extension: why developer devices are the real target GitHub breached via a malicious VS Code extension: why developer devices are the real target Written by Shaun Brown Published on: May 20, 2026 On May 19, GitHub disclosed that it was investigating unauthorized access to internal repositories. TeamPCP claims to have extracted data from roughly 4,000 private repos. The reported vector: a malicious VS Code extension installed …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain
- **T1176** — Browser Extensions
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1555** — Credentials from Password Stores
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1552.004** — Private Keys
- **T1083** — File and Directory Discovery
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1568.002** — Domain Generation Algorithms (Lookalike Domains)
- **T1041** — Exfiltration Over C2 Channel
- **T1213.003** — Code Repositories
- **T1530** — Data from Cloud Storage
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Malicious nrwl.angular-console VS Code extension drop (TeamPCP Nx Console campaign)

`UC_8_2` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_hash) as file_hash from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\.vscode\\extensions\\nrwl.angular-console-*" OR Filesystem.file_path="*/.vscode/extensions/nrwl.angular-console-*" OR Filesystem.file_hash IN ("1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1","43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let BadHashes = dynamic(["1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8","b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74","e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1","43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where (FolderPath has @"\.vscode\extensions\nrwl.angular-console-" or FolderPath has "/.vscode/extensions/nrwl.angular-console-")
    or SHA256 in (BadHashes)
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

### [LLM] VS Code Code.exe spawns shell running 'MCP setup' style curl/wget from nrwl/nx GitHub raw

`UC_8_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("Code.exe","Code - Insiders.exe","Cursor.exe","code-tunnel.exe") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe","node.exe","npx.cmd","npm.cmd") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | search (process="*nrwl/nx*" OR process="*raw.githubusercontent.com/nrwl*" OR (process="*curl*" AND process="*MCP*") OR (process="*wget*" AND process="*MCP*") OR process="*Invoke-WebRequest*nrwl*" OR process="*iwr*nrwl*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("Code.exe", "Code - Insiders.exe", "Cursor.exe", "code-tunnel.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe", "wsl.exe", "node.exe", "npx.cmd", "npm.cmd")
| where ProcessCommandLine has_any ("nrwl/nx", "raw.githubusercontent.com/nrwl", "github.com/nrwl/nx")
   or (ProcessCommandLine has_any ("curl", "wget", "Invoke-WebRequest", "iwr", "Start-BitsTransfer") and ProcessCommandLine has_any ("MCP", "mcp-setup", "mcpServers"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

### [LLM] VS Code child shell accessing 1Password / Claude Code / npm / AWS / GitHub crede

`UC_8_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("Code.exe","Code - Insiders.exe","Cursor.exe") Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe","node.exe") by Processes.dest Processes.user Processes.parent_process Processes.process Processes.process_name | `drop_dm_object_name(Processes)` | search (process="*.aws\\credentials*" OR process="*/.aws/credentials*" OR process="*.npmrc*" OR process="*.github_token*" OR process="*.git-credentials*" OR process="*\\.claude\\*" OR process="*/.claude/*" OR process="*claude_desktop_config*" OR process="*1Password*" OR process="*OnePassword*" OR process="*op-cli*" OR process="*id_rsa*" OR process="*authinfo*") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CredArtifacts = dynamic([
    ".aws\\credentials", "/.aws/credentials",
    ".npmrc", ".github_token", ".git-credentials",
    "\\.claude\\", "/.claude/", "claude_desktop_config",
    "1Password", "OnePassword", "op-cli",
    "id_rsa", "id_ed25519", "authinfo",
    "\\.config\\op\\", "/.config/op/",
    "Library/Group Containers/2BUA8C4S2C.com.1password"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("Code.exe", "Code - Insiders.exe", "Cursor.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh.exe", "wsl.exe", "node.exe")
| where ProcessCommandLine has_any (CredArtifacts)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, SHA256
| order by Timestamp asc
```

### [LLM] Egress to TeamPCP credential-stealer infrastructure (94.154.172.43 / 45.148.10.212 / lookalike domains)

`UC_8_5` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest IN ("94.154.172.43","45.148.10.212") OR All_Traffic.dest_host IN ("audit.checkmarx.cx","checkmarx.zone","scan.aquasecurtiy.org","git-tanstack.com","api.masscan.cloud")) by All_Traffic.src All_Traffic.dest All_Traffic.dest_host All_Traffic.app All_Traffic.user | `drop_dm_object_name(All_Traffic)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let BadIPs = dynamic(["94.154.172.43", "45.148.10.212"]);
let BadDomains = dynamic(["audit.checkmarx.cx", "checkmarx.zone", "scan.aquasecurtiy.org", "git-tanstack.com", "api.masscan.cloud"]);
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIP in (BadIPs) or RemoteUrl has_any (BadDomains)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp asc
```

### [LLM] Bulk GitHub repository clone fan-out from a single account (TeamPCP 3,800-repo exfil pattern)

`UC_8_6` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name IN ("git.exe","git","gh.exe","gh","curl.exe","curl","wget.exe","wget") (Processes.process="*git clone*" OR Processes.process="*api.github.com/repos*" OR Processes.process="*gh repo clone*" OR Processes.process="*github.com/*.git*") by Processes.dest Processes.user span=1h | `drop_dm_object_name(Processes)` | where count > 50 | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("git.exe", "gh.exe", "curl.exe", "wget.exe", "node.exe", "pwsh.exe", "powershell.exe")
| where ProcessCommandLine has_any ("git clone", "gh repo clone", "api.github.com/repos", ".git")
| where ProcessCommandLine has_any ("github.com/", "api.github.com", "raw.githubusercontent.com")
| summarize CloneCount = count(), Repos = make_set(extract(@"github\.com[:/]([\w\-\.]+/[\w\-\.]+?)(?:\.git|\s|$)", 1, ProcessCommandLine), 200), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, AccountName, bin(Timestamp, 1h)
| where CloneCount > 50
| order by CloneCount desc
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

### Article-specific behavioural hunt — GitHub Internal Repositories Breached via Malicious Nx Console VS Code Extension

`UC_8_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — GitHub Internal Repositories Breached via Malicious Nx Console VS Code Extension ```
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
// Article-specific bespoke detection — GitHub Internal Repositories Breached via Malicious Nx Console VS Code Extension
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


## Why this matters

Severity classified as **HIGH** based on: 7 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
