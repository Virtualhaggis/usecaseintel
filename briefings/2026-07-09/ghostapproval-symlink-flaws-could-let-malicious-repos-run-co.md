# [CRIT] GhostApproval Symlink Flaws Could Let Malicious Repos Run Code in AI Coding Agents

**Source:** The Hacker News
**Published:** 2026-07-09
**Article:** https://thehackernews.com/2026/07/ghostapproval-symlink-flaws-could-let.html

## Threat Profile

GhostApproval Symlink Flaws Could Let Malicious Repos Run Code in AI Coding Agents 
 Swati Khandelwal  Jul 09, 2026 AI Security / Vulnerability 
Researchers at  Wiz  found that a flaw in six popular AI coding assistants lets a booby-trapped code project quietly take control of a developer's computer. The assistant asks permission to edit one harmless-looking file, but the write lands on a sensitive one instead.
The affected tools are Amazon Q Developer, Anthropic's Claude Code, Augment, Cursor…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-12958`
- **CVE:** `CVE-2026-50549`
- **CVE:** `CVE-2026-12957`

## MITRE ATT&CK Techniques

- **T1176** — Browser Extensions
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1486** — Data Encrypted for Impact
- **T1003.001** — LSASS Memory
- **T1003** — OS Credential Dumping
- **T1021.002** — SMB/Windows Admin Shares
- **T1569.002** — Service Execution
- **T1195.002** — Compromise Software Supply Chain
- **T1098.004** — Account Manipulation: SSH Authorized Keys
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1021.004** — Remote Services: SSH
- **T1078** — Valid Accounts
- **T1036.005** — Masquerading: Match Legitimate Name or Location

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### AI coding agent writes SSH authorized_keys or shell rc via GhostApproval symlink

`UC_72_7` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action=created OR Filesystem.action=modified) AND (Filesystem.file_name="authorized_keys" OR Filesystem.file_name=".zshrc" OR Filesystem.file_name=".bashrc" OR Filesystem.file_name=".bash_profile" OR Filesystem.file_name=".profile" OR Filesystem.file_name=".zshenv" OR Filesystem.file_name=".zprofile") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | where match(process_name, "(?i)(node|code|cursor|windsurf|claude|antigravity|augment|amazonq)") | where NOT match(process_name, "(?i)(ssh-keygen|sshd)") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified")
| where InitiatingProcessAccountName !endswith "$"
| where (FileName == "authorized_keys" and FolderPath has "/.ssh/")
    or FileName in~ (".zshrc",".bashrc",".bash_profile",".profile",".zshenv",".zprofile",".zlogin")
| where InitiatingProcessFileName in~ ("node","node.exe","code","Code.exe","cursor","Cursor","cursor.exe","windsurf","Windsurf","windsurf.exe","claude","antigravity","augment","python","python3")
    or InitiatingProcessCommandLine has_any ("amazonq","amazon-q","language-server","cursor","windsurf","claude","augment","antigravity")
| where not(InitiatingProcessFileName in~ ("ssh-keygen","sshd"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Amazon Q / AI agent spawns shell child from poisoned .amazonq/mcp.json (CVE-2026-12957)

`UC_72_8` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","node.exe","code","Code.exe","cursor","windsurf","claude","antigravity","augment") OR Processes.parent_process="*amazonq*" OR Processes.parent_process="*mcp.json*" OR Processes.parent_process="*language-server*") AND (Processes.process_name IN ("bash","sh","zsh","dash","cmd.exe","powershell.exe","pwsh","python","python3","osascript")) AND (Processes.process="*curl*" OR Processes.process="*wget*" OR Processes.process="*chmod*" OR Processes.process="*base64*" OR Processes.process="*.aws*" OR Processes.process="*authorized_keys*" OR Processes.parent_process="*mcp.json*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessAccountName !endswith "$"
| where InitiatingProcessFileName in~ ("node","node.exe","code","Code.exe","cursor","Cursor","cursor.exe","windsurf","Windsurf","windsurf.exe","claude","antigravity","augment")
    or InitiatingProcessCommandLine has_any ("amazonq","amazon-q","language-server",".amazonq/mcp.json","mcp.json")
| where FileName in~ ("bash","sh","zsh","dash","cmd.exe","powershell.exe","pwsh","python","python3","osascript")
| where ProcessCommandLine has_any ("curl","wget","chmod","base64",".aws/credentials",".aws\\credentials","authorized_keys","aws_access_key")
    or InitiatingProcessCommandLine has "mcp.json"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

### SSH authorized_keys planted then remote SSH logon (GhostApproval key-injection use)

`UC_72_9` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` min(_time) as KeyWriteTime from datamodel=Endpoint.Filesystem where Filesystem.file_name="authorized_keys" AND Filesystem.file_path="*/.ssh/*" AND (Filesystem.action=created OR Filesystem.action=modified) by Filesystem.dest Filesystem.process_name | `drop_dm_object_name(Filesystem)` | join type=inner dest [| tstats `summariesonly` min(_time) as LogonTime from datamodel=Authentication where Authentication.action=success AND (Authentication.app="sshd" OR Authentication.signature="ssh") by Authentication.dest Authentication.src Authentication.user | `drop_dm_object_name(Authentication)`] | where LogonTime >= KeyWriteTime AND LogonTime <= KeyWriteTime+3600 | eval DelaySec=LogonTime-KeyWriteTime | convert ctime(KeyWriteTime) ctime(LogonTime) | table dest process_name KeyWriteTime LogonTime DelaySec src user
```

**Defender KQL:**
```kql
let win = 1h;
let keyWrites = DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName == "authorized_keys" and FolderPath has "/.ssh/"
    | where ActionType in ("FileCreated","FileModified")
    | project KeyWriteTime = Timestamp, DeviceId, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine;
DeviceLogonEvents
| where Timestamp > ago(14d)
| where ActionType == "LogonSuccess"
| where LogonType in ("Network","RemoteInteractive") or Protocol =~ "Ssh"
| where RemoteIPType == "Public"
| join kind=inner keyWrites on DeviceId
| where Timestamp between (KeyWriteTime .. KeyWriteTime + win)
| extend DelaySec = datetime_diff('second', Timestamp, KeyWriteTime)
| project KeyWriteTime, LogonTime = Timestamp, DeviceName, AccountName, RemoteIP, DelaySec, KeyWriter = InitiatingProcessFileName, InitiatingProcessCommandLine
| order by LogonTime desc
```

### Symlink created in repo pointing to SSH/AWS/shell files (GhostApproval staging)

`UC_72_10` · phase: **weapon** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.process_name="ln" AND Processes.process="*-s*") OR (Processes.process="*mklink*") OR (Processes.process="*SymbolicLink*")) AND (Processes.process="*authorized_keys*" OR Processes.process="*/.ssh*" OR Processes.process="*.zshrc*" OR Processes.process="*.bashrc*" OR Processes.process="*.aws*" OR Processes.process="*/etc/*" OR Processes.process="*System32*" OR Processes.process="*..*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where AccountName !endswith "$"
| where (FileName =~ "ln" and ProcessCommandLine has "-s")
    or (FileName in~ ("cmd.exe") and ProcessCommandLine has "mklink")
    or (FileName in~ ("powershell.exe","pwsh") and ProcessCommandLine has "SymbolicLink")
| where ProcessCommandLine has_any ("authorized_keys","/.ssh",".zshrc",".bashrc",".bash_profile",".aws","/etc/","System32","..\\..","../..")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-12958`, `CVE-2026-50549`, `CVE-2026-12957`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 11 use case(s) fired, 18 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
