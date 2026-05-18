# [CRIT] Glassworm Is Back: A New Wave of Invisible Unicode Attacks Hits Hundreds of Repositories

**Source:** Aikido
**Published:** 2026-03-13
**Article:** https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode

## Threat Profile

Blog Vulnerabilities & Threats Glassworm Is Back: A New Wave of Invisible Unicode Attacks Hits Hundreds of Repositories Glassworm Is Back: A New Wave of Invisible Unicode Attacks Hits Hundreds of Repositories Written by Ilyas Makari Published on: Mar 13, 2026 The invisible threat we've been tracking for nearly a year is back. While the PolinRider campaign has been making headlines for compromising hundreds of GitHub repositories, we are separately seeing a new wave of Glassworm activity hitting …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1027** — Obfuscated Files or Information
- **T1140** — Deobfuscate/Decode Files or Information

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GlassWorm Mar 2026 wave — compromised npm/VS Code package artifacts on disk

`UC_355_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\@aifabrix\\miso-client\\*" OR Filesystem.file_path="*/node_modules/@aifabrix/miso-client/*" OR Filesystem.file_path="*\\node_modules\\@iflow-mcp\\watercrawl-watercrawl-mcp\\*" OR Filesystem.file_path="*/node_modules/@iflow-mcp/watercrawl-watercrawl-mcp/*" OR Filesystem.file_path="*\\.vscode\\extensions\\quartz.quartz-markdown-editor-*" OR Filesystem.file_path="*/.vscode/extensions/quartz.quartz-markdown-editor-*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process_guid | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime) | sort 0 - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\node_modules\@aifabrix\miso-client"
    or FolderPath has @"\node_modules\@iflow-mcp\watercrawl-watercrawl-mcp"
    or FolderPath has @"\.vscode\extensions\quartz.quartz-markdown-editor-"
    or FolderPath has "/node_modules/@aifabrix/miso-client"
    or FolderPath has "/node_modules/@iflow-mcp/watercrawl-watercrawl-mcp"
    or FolderPath has "/.vscode/extensions/quartz.quartz-markdown-editor-"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### [LLM] GlassWorm invisible-Unicode decoder signature (variation-selector eval loader) in process cmdline

`UC_355_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("node.exe","node","npm.exe","npx.exe","pwsh.exe","powershell.exe","cmd.exe","bash","sh") Processes.process="*0xFE00*" Processes.process="*0xE0100*" Processes.process="*codePointAt*" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process Processes.process_guid | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort 0 - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where ProcessCommandLine has "0xFE00"
   and ProcessCommandLine has "0xE0100"
   and ProcessCommandLine has "codePointAt"
| project Timestamp, DeviceName, AccountName,
          Parent = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine,
          SHA256
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


## Why this matters

Severity classified as **CRIT** based on: 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
