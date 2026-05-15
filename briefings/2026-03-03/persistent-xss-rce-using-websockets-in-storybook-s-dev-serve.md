# [CRIT] Persistent XSS/RCE using WebSockets in Storybook’s dev server

**Source:** Aikido
**Published:** 2026-03-03
**Article:** https://www.aikido.dev/blog/storybooks-websockets-attack

## Threat Profile

Blog Vulnerabilities & Threats Persistent XSS/RCE using WebSockets in Storybook’s dev server Persistent XSS/RCE using WebSockets in Storybook’s dev server Written by Robbe Verwilghen Published on: Mar 3, 2026 Aikido Attack , our AI pentest product, found a WebSocket hijacking vulnerability in Storybook's dev server that can lead to persistent XSS and remote code execution. If unnoticed, the payload could end up in version control, the CI/CD pipeline and the production build of Storybook. Storybo…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-27148`

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **T1027** — Obfuscated Files or Information
- **T1133** — External Remote Services
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1106** — Native API

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Storybook CVE-2026-27148 — story file written with JS injection markers in filename

`UC_373_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\src\\stories\\*" OR Filesystem.file_path="*/src/stories/*") AND (Filesystem.file_name="*.stories.ts" OR Filesystem.file_name="*.stories.tsx" OR Filesystem.file_name="*.stories.js" OR Filesystem.file_name="*.stories.jsx" OR Filesystem.file_name="*.tsx" OR Filesystem.file_name="*.ts") AND (Filesystem.file_name="*';*" OR Filesystem.file_name="*document.domain*" OR Filesystem.file_name="*child_process*" OR Filesystem.file_name="*execSync*" OR Filesystem.file_name="*RCE_PROOF*" OR Filesystem.file_name="*alert(*" OR Filesystem.file_name="*require(*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_guid Filesystem.action | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has @"\src\stories\" or FolderPath has "/src/stories/"
| where FileName endswith ".stories.ts" or FileName endswith ".stories.tsx"
    or FileName endswith ".stories.js" or FileName endswith ".stories.jsx"
    or FileName endswith ".tsx" or FileName endswith ".ts"
    or FileName endswith ".jsx" or FileName endswith ".js"
| where FileName has_any ("';", "document.domain", "child_process", "execSync", "RCE_PROOF", "alert(", "require(", "';var", "console.log('RCE")
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","yarn.exe","pnpm.exe","npx.exe","node")
   or InitiatingProcessCommandLine has_any ("storybook","@storybook/","storybook-server-channel")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FolderPath, FileName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### [LLM] Storybook dev server bound to non-loopback interface (publicly exposed CVE-2026-27148 attack surface)

`UC_373_6` · phase: **recon** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Ports where All_Ports.dest_port=6006 AND All_Ports.transport="tcp" AND NOT (All_Ports.dest IN ("127.0.0.1","::1","localhost")) by All_Ports.dest All_Ports.user All_Ports.process_name All_Ports.process_guid | `drop_dm_object_name(All_Ports)` | join type=left process_guid [| tstats `summariesonly` values(Processes.process) as process_cmd from datamodel=Endpoint.Processes where (Processes.process="*storybook*" OR Processes.process="*@storybook/*" OR Processes.process="*start-storybook*") by Processes.process_guid | `drop_dm_object_name(Processes)`] | where isnotnull(process_cmd) | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "ListeningConnectionCreated"
| where LocalPort == 6006
| where LocalIP !startswith "127." and LocalIP != "::1"
| where InitiatingProcessFileName has_any ("node","node.exe")
   or InitiatingProcessCommandLine has_any ("storybook","@storybook/","start-storybook","storybook dev")
| extend Internet_Bound = iff(LocalIP == "0.0.0.0" or LocalIP == "::", "all-interfaces", "specific")
| project Timestamp, DeviceName, InitiatingProcessAccountName, LocalIP, LocalPort, Internet_Bound,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath
| order by Timestamp desc
```

### [LLM] Node test runner (Vitest/Jest) spawning OS shell or recon binary from Storybook context

`UC_373_7` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","node","npx.exe","npm.exe","pnpm.exe","yarn.exe") AND (Processes.parent_process="*vitest*" OR Processes.parent_process="*jest*" OR Processes.parent_process="*storybook*" OR Processes.parent_process="*portable-stories*" OR Processes.parent_process="*\\src\\stories\\*" OR Processes.parent_process="*/src/stories/*") AND Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh.exe","bash.exe","whoami.exe","hostname.exe","wmic.exe","curl.exe","wget.exe","net.exe","reg.exe") by host Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node","npx.exe","npm.exe","pnpm.exe","yarn.exe")
| where InitiatingProcessCommandLine has_any ("vitest","jest","storybook","portable-stories",@"\src\stories\","/src/stories/","@storybook/")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh.exe","bash.exe","whoami.exe","hostname.exe","wmic.exe","curl.exe","wget.exe","net.exe","reg.exe","ipconfig.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
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

### Article-specific behavioural hunt — Persistent XSS/RCE using WebSockets in Storybook’s dev server

`UC_373_4` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Persistent XSS/RCE using WebSockets in Storybook’s dev server ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Persistent XSS/RCE using WebSockets in Storybook’s dev server
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-27148`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 8 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
