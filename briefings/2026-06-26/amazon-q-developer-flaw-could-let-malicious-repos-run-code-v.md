# [CRIT] Amazon Q Developer Flaw Could Let Malicious Repos Run Code via MCP Configs

**Source:** The Hacker News
**Published:** 2026-06-26
**Article:** https://thehackernews.com/2026/06/amazon-q-developer-flaw-could-let.html

## Threat Profile

Amazon Q Developer Flaw Could Let Malicious Repos Run Code via MCP Configs 
 Swati Khandelwal  Jun 26, 2026 AI Security / Vulnerability 
A high-severity flaw in Amazon Q Developer let a malicious repository run commands and steal a developer's cloud credentials. The path was short: a developer opens the repo, trusts the workspace, and Amazon Q does the rest. Amazon has patched it.
Tracked as  CVE-2026-12957  (CVSS 8.5), the bug sat in how Amazon's AI coding assistant handled Model Context Prot…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-12957`
- **CVE:** `CVE-2026-12958`

## MITRE ATT&CK Techniques

- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1552** — Unsecured Credentials
- **T1567** — Exfiltration Over Web Service
- **T1580** — Cloud Infrastructure Discovery
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious .amazonq/mcp.json MCP config delivered via cloned repository

`UC_83_3` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="mcp.json" Filesystem.file_path="*\\.amazonq\\*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "mcp.json"
| where FolderPath contains ".amazonq"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Amazon Q MCP payload: aws sts get-caller-identity piped to web exfil

`UC_83_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*get-caller-identity*" (Processes.process="*curl*" OR Processes.process="*wget*" OR Processes.process="*Invoke-WebRequest*" OR Processes.process="*Invoke-RestMethod*" OR Processes.process="*-d @-*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "get-caller-identity"
| where ProcessCommandLine has_any ("curl","wget","Invoke-WebRequest","Invoke-RestMethod","-d @-","ncat")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Developer IDE / Amazon Q language server spawns shell running cloud-credential commands

`UC_83_5` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="bash.exe" OR Processes.process_name="sh.exe" OR Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="wsl.exe") (Processes.parent_process_name="Code.exe" OR Processes.parent_process_name="idea64.exe" OR Processes.parent_process_name="pycharm64.exe" OR Processes.parent_process_name="eclipse.exe" OR Processes.parent_process_name="devenv.exe" OR Processes.parent_process_name="node.exe") (Processes.process="*get-caller-identity*" OR Processes.process="*aws sts*" OR Processes.process="*secretsmanager*" OR Processes.process="*.aws*credentials*" OR Processes.process="*curl*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("bash.exe","sh.exe","wsl.exe","cmd.exe","powershell.exe","pwsh.exe")
| where InitiatingProcessFileName in~ ("Code.exe","idea64.exe","idea.exe","pycharm64.exe","webstorm64.exe","clion64.exe","eclipse.exe","devenv.exe","ServiceHub.Host.dotnet.x64.exe","node.exe")
| where ProcessCommandLine has_any ("get-caller-identity","aws sts","secretsmanager",".aws\\credentials","/.aws/","curl","Invoke-WebRequest")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Exposure: endpoints running vulnerable Language Servers for AWS (CVE-2026-12957/12958)

`UC_83_6` · phase: **recon** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId in ("CVE-2026-12957","CVE-2026-12958")
| project DeviceName, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-12957`, `CVE-2026-12958`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
