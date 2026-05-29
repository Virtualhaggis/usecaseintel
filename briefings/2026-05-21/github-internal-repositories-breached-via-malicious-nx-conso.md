# [HIGH] GitHub Internal Repositories Breached via Malicious Nx Console VS Code Extension

**Source:** The Hacker News
**Published:** 2026-05-21
**Article:** https://thehackernews.com/2026/05/github-internal-repositories-breached.html

## Threat Profile

GitHub Internal Repositories Breached via Malicious Nx Console VS Code Extension 
 Ravie Lakshmanan  May 21, 2026 Supply Chain Attack / Developer Tools 
GitHub on Wednesday officially confirmed that the breach of its internal repositories was the result of a compromise of an employee device involving a poisoned version of the Nx Console Microsoft Visual Studio Code (VS Code) extension. 
The development comes as the Nx team revealed that the extension, nrwl.angular-console , was breached after …

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `94.154.172.43`
- **IPv4 (defanged):** `45.148.10.212`
- **Domain (defanged):** `audit.checkmarx.cx`
- **Domain (defanged):** `checkmarx.zone`
- **Domain (defanged):** `scan.aquasecurtiy.org`
- **Domain (defanged):** `git-tanstack.com`
- **Domain (defanged):** `api.masscan.cloud`
- **SHA256:** `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`
- **SHA256:** `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74`
- **SHA256:** `e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1`
- **SHA256:** `43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9`
- **SHA1:** `558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2`
- **SHA1:** `ba642fe2c7c65e42dd7f6444b83023dc6827e08c`
- **SHA1:** `acfc3f957a63b4cde93ff645f2b6bf26a8ed1bbf`
- **SHA1:** `9d88f040c44b5f4d5f9db15ff89310776c168e99`

## MITRE ATT&CK Techniques

- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1071** — Application Layer Protocol
- **T1027** — Obfuscated Files or Information
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

`UC_94_6` · phase: **delivery** · confidence: **High**

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

`UC_94_7` · phase: **install** · confidence: **High**

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

`UC_94_8` · phase: **actions** · confidence: **High**

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

`UC_94_9` · phase: **c2** · confidence: **High**

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

`UC_94_10` · phase: **actions** · confidence: **Medium**

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

### Ransomware-style mass file rename / extension change

`UC_RANSOM_ENCRYPT` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count, dc(Filesystem.file_name) AS files
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("modified","renamed")
    by Filesystem.dest, Filesystem.user, _time span=1m
| `drop_dm_object_name(Filesystem)`
| where files > 200
| sort - files
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileRenamed","FileModified")
| summarize files = dcount(FileName) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1m)
| where files > 200    // empirical: > 200 unique-file renames in 1m by one account on one host
                       //            is well above the P99 of legitimate bulk-tooling
| order by files desc
```

### LSASS process access / dump (credential theft)

`UC_LSASS` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process="*lsass*" OR Processes.process="*sekurlsa*"
        OR Processes.process="*MiniDump*" OR Processes.process="*comsvcs.dll*MiniDump*"
        OR Processes.process="*procdump*lsass*")
       OR (Processes.process_name="rundll32.exe" AND Processes.process="*comsvcs*MiniDump*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsSense.exe","MsMpEng.exe","csrss.exe",
                                          "svchost.exe","wininit.exe","services.exe",
                                          "lsm.exe","SearchProtocolHost.exe")
| project Timestamp, DeviceName, ActionType, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, AccountName
| order by Timestamp desc
```

### Remote service execution — PsExec / SMB lateral movement

`UC_LATERAL_PSEXEC` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
       OR (Processes.process_name="wmic.exe" AND Processes.process="*/node:*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("psexec.exe","psexesvc.exe","paexec.exe","smbexec.py")
   or (FileName =~ "wmic.exe" and ProcessCommandLine has "/node:")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
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
  - IP / domain IOC(s): `94.154.172.43`, `45.148.10.212`, `audit.checkmarx.cx`, `checkmarx.zone`, `scan.aquasecurtiy.org`, `git-tanstack.com`, `api.masscan.cloud`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`, `b0cefb66b953e5184b6adb3035e9e267335ac5eabfe1848e07834777b9397b74`, `e7347d90653efc565f03733a95e9209d78f9cfa81e31ff2b2dd9d48d75a4b8b1`, `43f2b001846c4966073ebffa5be8f15e491a1e7d32bbd805d57406ff540e0dd9`, `558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2`, `ba642fe2c7c65e42dd7f6444b83023dc6827e08c`, `acfc3f957a63b4cde93ff645f2b6bf26a8ed1bbf`, `9d88f040c44b5f4d5f9db15ff89310776c168e99`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 11 use case(s) fired, 22 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
