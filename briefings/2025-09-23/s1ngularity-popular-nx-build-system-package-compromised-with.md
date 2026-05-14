# [HIGH] s1ngularity: Popular Nx Build System Package Compromised with Data-Stealing Malware

**Source:** StepSecurity
**Published:** 2025-09-23
**Article:** https://www.stepsecurity.io/blog/supply-chain-security-alert-popular-nx-build-system-package-compromised-with-data-stealing-malware

## Threat Profile

Back to Blog Threat Intel s1ngularity: Popular Nx Build System Package Compromised with Data-Stealing Malware s1ngularity attack hijacked Nx package on npm to steal cryptocurrency wallets, GitHub/npm tokens, SSH keys, and environment secrets - the first documented case of malware weaponizing AI CLI tools for reconnaissance and data exfiltration. Ashish Kurmi View LinkedIn August 27, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav.…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1119** — Automated Collection
- **T1074.001** — Data Staged: Local Data Staging
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1529** — System Shutdown/Reboot
- **T1485** — Data Destruction

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] s1ngularity nx: AI CLI assistant invoked with permission-bypass flags (Claude/Gemini/Q)

`UC_642_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name IN ("claude","gemini","q") OR Processes.process IN ("*claude *","*gemini *","* q chat *")) AND (Processes.process="*--dangerously-skip-permissions*" OR Processes.process="*--yolo*" OR Processes.process="*--trust-all-tools*") by host Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// s1ngularity: AI CLI launched with safety-bypass flags as part of credential recon
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("claude","gemini","q")
   or FolderPath endswith "/claude" or FolderPath endswith "/gemini" or FolderPath endswith "/q"
| where ProcessCommandLine has_any ("--dangerously-skip-permissions","--yolo","--trust-all-tools")
// the s1ngularity prompt writes to /tmp/inventory.txt — boosts confidence when present
| extend HasInventoryPrompt = ProcessCommandLine has "/tmp/inventory.txt" or ProcessCommandLine has "keystore" or ProcessCommandLine has "metamask"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          GrandParent = InitiatingProcessParentFileName,
          HasInventoryPrompt, SHA256
| order by Timestamp desc
```

### [LLM] s1ngularity nx: /tmp/inventory.txt staging file created on host

`UC_642_6` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.process_name) as creating_proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("/tmp/inventory.txt","/tmp/inventory.txt.bak") by host Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// s1ngularity: hard-coded staging file /tmp/inventory.txt created
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("inventory.txt","inventory.txt.bak")
| where FolderPath in~ ("/tmp","/tmp/")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          CreatedBy = InitiatingProcessFileName,
          CreatedByCmd = InitiatingProcessCommandLine,
          CreatedByFolder = InitiatingProcessFolderPath,
          ParentOfCreator = InitiatingProcessParentFileName,
          User = InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] s1ngularity nx: node modifies ~/.bashrc or ~/.zshrc to inject `sudo shutdown -h 0`

`UC_642_7` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path values(Filesystem.process_name) as proc from datamodel=Endpoint.Filesystem where (Filesystem.file_name=".bashrc" OR Filesystem.file_name=".zshrc" OR Filesystem.file_name=".bash_profile" OR Filesystem.file_name=".profile") AND Filesystem.process_name IN ("node","npm","npx","yarn","pnpm") by host Filesystem.file_name Filesystem.process_name Filesystem.user | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// s1ngularity: node (post-install) modifies shell rc files — pair with shutdown content where available
let RcWritesByNode = DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType in ("FileModified","FileCreated")
    | where FileName in~ (".bashrc",".zshrc",".bash_profile",".profile")
    | where InitiatingProcessFileName in~ ("node","nodejs")
    | project Timestamp, DeviceName, FolderPath, FileName,
              NodeCmd = InitiatingProcessCommandLine,
              NodeParent = InitiatingProcessParentFileName,
              User = InitiatingProcessAccountName;
// optional enrichment — a follow-on shell that actually attempts shutdown
let ShutdownFromShellRc = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("bash","zsh","sh","dash")
    | where FileName =~ "shutdown" or FileName =~ "sudo"
    | where ProcessCommandLine has_all ("shutdown","-h","0")
    | project ShutdownTime = Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName;
RcWritesByNode
| join kind=leftouter ShutdownFromShellRc on DeviceName
| order by Timestamp desc
```

### Crypto-wallet file/keystore access by non-wallet process

`UC_CRYPTO_WALLET` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*\Ethereum\keystore\*"
        OR Filesystem.file_path="*\Bitcoin\wallet.dat"
        OR Filesystem.file_path="*\Exodus\exodus.wallet*"
        OR Filesystem.file_path="*\Electrum\wallets\*"
        OR Filesystem.file_path="*\MetaMask\*"
        OR Filesystem.file_path="*\Phantom\*"
        OR Filesystem.file_path="*\Atomic\Local Storage\*")
      AND NOT Filesystem.process_name IN ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
    by Filesystem.dest, Filesystem.process_name, Filesystem.file_path, Filesystem.user
| `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessAccountName !endswith "$"
| where FolderPath has_any (@"\Ethereum\keystore\", @"\Bitcoin\", @"\Exodus\", @"\Electrum\wallets\", @"\MetaMask\", @"\Phantom\", @"\Atomic\Local Storage\")
| where InitiatingProcessFileName !in~ ("MetaMask.exe","Exodus.exe","Atomic.exe","electrum.exe","Bitcoin.exe","Phantom.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FolderPath, FileName, ActionType
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

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
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

### Article-specific behavioural hunt — s1ngularity: Popular Nx Build System Package Compromised with Data-Stealing Malw

`UC_642_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — s1ngularity: Popular Nx Build System Package Compromised with Data-Stealing Malw ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("telemetry.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/inventory.txt*" OR Filesystem.file_path="*/tmp/inventory.txt.bak*" OR Filesystem.file_path="*/tmp/pr-message.txt*" OR Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_name IN ("telemetry.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — s1ngularity: Popular Nx Build System Package Compromised with Data-Stealing Malw
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("telemetry.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/inventory.txt", "/tmp/inventory.txt.bak", "/tmp/pr-message.txt", "/usr/bin/env") or FileName in~ ("telemetry.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 8 use case(s) fired, 14 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
