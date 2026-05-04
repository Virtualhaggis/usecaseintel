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
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1204.003** — User Execution: Malicious Image
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Git hook execution from .git/hooks via Cursor agent autonomous git checkout (CVE-2026-26268)

`UC_47_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name=git.exe AND (Processes.process="*\\.git\\hooks\\*" OR Processes.process="*/.git/hooks/*" OR Processes.process_path="*\\.git\\hooks\\*" OR Processes.process_path="*/.git/hooks/*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_path Processes.process_hash | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | eval cursor_context=if(match(parent_process,"(?i)cursor") OR match(process_path,"(?i)cursor"),"yes","no")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("git.exe","git")
| where ProcessCommandLine has_any (@"\.git\hooks\", "/.git/hooks/")
   or FolderPath has_any (@"\.git\hooks\", "/.git/hooks/")
   or InitiatingProcessCommandLine has_any (@"\.git\hooks\", "/.git/hooks/")
| extend CursorContext = iff(
      InitiatingProcessParentFileName has "Cursor"
      or InitiatingProcessCommandLine has_cs "Cursor"
      or InitiatingProcessFolderPath has "Cursor", true, false)
| project Timestamp, DeviceName, AccountName,
          GrandParent = InitiatingProcessParentFileName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName, ChildCmd = ProcessCommandLine,
          ChildFolder = FolderPath, SHA256, CursorContext
| order by CursorContext desc, Timestamp desc
```

### [LLM] Gemini CLI --yolo mode spawning shell child via run_shell_command (CVSS 10 workspace-trust bypass)

`UC_47_5` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN (node.exe,node) AND (Processes.parent_process="*@google/gemini-cli*" OR Processes.parent_process="*gemini-cli/dist*" OR Processes.parent_process="*gemini-cli/index*" OR Processes.parent_process="* gemini *") AND (Processes.parent_process="*--yolo*" OR Processes.parent_process="* -y *") AND Processes.process_name IN (sh.exe,bash.exe,cmd.exe,powershell.exe,pwsh.exe,sh,bash,zsh) by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessCommandLine has_any (
      "@google/gemini-cli",
      "gemini-cli/dist",
      "gemini-cli/index",
      "/gemini ",
      "\\gemini ")
| where InitiatingProcessCommandLine has_any ("--yolo"," -y ")
| where FileName in~ ("sh.exe","bash.exe","cmd.exe","powershell.exe","pwsh.exe","sh","bash","zsh")
| project Timestamp, DeviceName, AccountName,
          GeminiCmd = InitiatingProcessCommandLine,
          GeminiPath = InitiatingProcessFolderPath,
          ChildShell = FileName,
          ChildCmd = ProcessCommandLine,
          ChildFolder = FolderPath,
          IsRemoteSession = AdditionalFields
| order by Timestamp desc
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
| where InitiatingProcessAccountName !endswith "$"
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
  - CVE(s): `CVE-2026-26268`, `CVE-2026-33626`, `CVE-2026-32202`, `CVE-2026-3854`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
