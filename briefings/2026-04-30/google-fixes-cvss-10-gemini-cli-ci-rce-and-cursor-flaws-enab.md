# [CRIT] Google Fixes CVSS 10 Gemini CLI CI RCE and Cursor Flaws Enable Code Execution

**Source:** The Hacker News
**Published:** 2026-04-30
**Article:** https://thehackernews.com/2026/04/google-fixes-cvss-10-gemini-cli-ci-rce.html

## Threat Profile

Google Fixes CVSS 10 Gemini CLI CI RCE and Cursor Flaws Enable Code Execution 
 Ravie Lakshmanan  Apr 30, 2026 AI Security / Vulnerability 
Google has addressed a maximum severity security flaw in Gemini CLI -- the "@google/gemini-cli" npm package and the "google-github-actions/run-gemini-cli" GitHub Actions workflow -- that could have allowed attackers to execute arbitrary commands on host systems.
"The vulnerability allowed an unprivileged external attacker to force their own malicious conte…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-26268`
- **CVE:** `CVE-2026-33626`
- **CVE:** `CVE-2026-32202`
- **CVE:** `CVE-2026-3854`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1611** — Escape to Host
- **T1546** — Event Triggered Execution
- **T1059.004** — Unix Shell
- **T1204.002** — User Execution: Malicious File
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1555** — Credentials from Password Stores
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1005** — Data from Local System

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Gemini CLI headless workspace-trust RCE via attacker-controlled .gemini/ in CI runner

`UC_43_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process IN ("*@google/gemini-cli*","*gemini-cli*","*run-gemini-cli*","*gemini *") OR Processes.parent_process_name IN ("gemini","gemini.exe")) AND Processes.process_name IN ("sh","bash","dash","zsh","cmd.exe","powershell.exe","pwsh.exe","python","python3","node","node.exe","curl","wget") AND (Processes.parent_process IN ("*.gemini/*","*.gemini\\*","*GEMINI_TRUST_WORKSPACE*","*--yolo*","*headless*") OR Processes.process IN ("*.gemini/*","*.gemini\\*")) by host Processes.user Processes.parent_process Processes.process Processes.process_path Processes.process_current_directory | `drop_dm_object_name(Processes)` | where like(process_current_directory,"%/_work/%") OR like(process_current_directory,"%runner%") OR like(process_current_directory,"%actions-runner%") OR like(parent_process,"%run-gemini-cli%") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let geminiParents = dynamic(["@google/gemini-cli","gemini-cli","run-gemini-cli","gemini.js"]);
let shells = dynamic(["cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","zsh","python.exe","python3","python","node.exe","node","curl.exe","wget.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (InitiatingProcessCommandLine has_any (geminiParents) or InitiatingProcessFileName =~ "gemini" or InitiatingProcessParentFileName =~ "gemini")
| where FileName in~ (shells)
| where InitiatingProcessCommandLine has_any (".gemini/",".gemini\\","--yolo","headless","GEMINI_TRUST_WORKSPACE","run_shell_command")
     or FolderPath has_any (".gemini/",".gemini\\")
     or InitiatingProcessFolderPath has_any ("actions-runner","_work","/runner/")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FileName, ProcessCommandLine, FolderPath, InitiatingProcessFolderPath
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(7d)
    | where FolderPath has ".gemini" and FileName in~ (".env","settings.json","GEMINI.md")
    | project DeviceName, GeminiCfgFile=FileName, GeminiCfgPath=FolderPath, GeminiCfgTime=Timestamp
) on DeviceName
| where isnotempty(GeminiCfgPath) or InitiatingProcessCommandLine has ".gemini"
```

### [LLM] Cursor IDE child process spawned from embedded bare-repo .git/hooks (CVE-2026-26268)

`UC_43_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("Cursor.exe","Cursor","Cursor Helper","Cursor Helper (Plugin).exe","Cursor Helper (Renderer).exe") OR Processes.parent_process IN ("*Cursor.exe*","*/Cursor.app/*","*\\Cursor\\resources\\app*")) AND (Processes.process_path IN ("*\\.git\\hooks\\*","*/.git/hooks/*") OR Processes.process IN ("*post-checkout*","*pre-commit*","*post-commit*","*post-merge*","*pre-push*","*post-rewrite*") OR Processes.parent_process IN ("*git checkout*","*git --git-dir*")) by host Processes.user Processes.parent_process Processes.process Processes.process_path Processes.process_current_directory | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let cursorBins = dynamic(["Cursor.exe","Cursor","Cursor Helper","Cursor Helper (Plugin).exe","Cursor Helper (Renderer).exe"]);
let hookNames = dynamic(["post-checkout","pre-commit","post-commit","post-merge","pre-push","post-rewrite","prepare-commit-msg"]);
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ (cursorBins)
   or InitiatingProcessParentFileName in~ (cursorBins)
   or InitiatingProcessFolderPath has_any ("\\Cursor\\","/Cursor.app/","/cursor/resources/app")
| where FolderPath has_any ("\\.git\\hooks\\","/.git/hooks/")
     or FileName in~ (hookNames)
     or ProcessCommandLine has_any (".git/hooks/",".git\\hooks\\","git --git-dir","git checkout master")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName =~ "AGENTS.md" or FolderPath has_any ("\\.git\\hooks\\","/.git/hooks/")
    | summarize AgentsMdSeen=any(FileName=="AGENTS.md"), HookFileWritten=any(FolderPath has ".git/hooks" or FolderPath has ".git\\hooks\\") by DeviceName
) on DeviceName
```

### [LLM] CursorJacking: non-Cursor process reading Cursor SQLite credential store (state.vscdb)

`UC_43_6` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*\\Cursor\\User\\globalStorage\\state.vscdb*","*/Cursor/User/globalStorage/state.vscdb*","*/Library/Application Support/Cursor/User/globalStorage/state.vscdb*") OR Filesystem.file_name IN ("state.vscdb","state.vscdb.backup")) AND NOT Filesystem.process_name IN ("Cursor.exe","Cursor","Cursor Helper","Cursor Helper (Plugin).exe","Cursor Helper (Renderer).exe","Cursor Helper (GPU).exe") by host Filesystem.user Filesystem.process_name Filesystem.process_path Filesystem.file_path Filesystem.file_name Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let cursorProcs = dynamic(["Cursor.exe","Cursor","Cursor Helper","Cursor Helper (Plugin).exe","Cursor Helper (Renderer).exe","Cursor Helper (GPU).exe"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where FileName in~ ("state.vscdb","state.vscdb.backup")
| where FolderPath has_any ("\\Cursor\\User\\globalStorage","/Cursor/User/globalStorage","/Library/Application Support/Cursor/User/globalStorage")
| where InitiatingProcessFileName !in~ (cursorProcs)
| where InitiatingProcessFolderPath !has "\\Cursor\\" and InitiatingProcessFolderPath !has "/Cursor.app/"
| project Timestamp, DeviceName, AccountName, ActionType, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, FileName, FolderPath
| summarize Reads=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp) by DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FolderPath
```

### Suspicious browser extension installation

`UC_BROWSER_EXT` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Registry
    where (Registry.registry_path="*\Software\Google\Chrome\Extensions\*"
        OR Registry.registry_path="*\Software\Microsoft\Edge\Extensions\*"
        OR Registry.registry_path="*\Software\Mozilla\Firefox\Extensions\*")
    by Registry.dest, Registry.registry_path, Registry.registry_value_data, Registry.registry_value_name, Registry.user
| `drop_dm_object_name(Registry)`
```

**Defender KQL:**
```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has_any ("\Software\Google\Chrome\Extensions\","\Software\Microsoft\Edge\Extensions\","\Software\Mozilla\Firefox\Extensions\")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData,
          InitiatingProcessFileName, InitiatingProcessAccountName
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
| where FolderPath has_any ("\Google\Chrome\User Data\","\Microsoft\Edge\User Data\","\Mozilla\Firefox\Profiles\")
| where FileName in~ ("Login Data","Cookies","logins.json","cookies.sqlite")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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
| where InitiatingProcessFileName in~ ("setup.exe","installer.exe","update.exe")
| where FileName in~ ("powershell.exe","cmd.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe","wmic.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-26268`, `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 7 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
