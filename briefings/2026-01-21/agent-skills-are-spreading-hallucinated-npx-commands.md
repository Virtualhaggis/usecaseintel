# [HIGH] Agent Skills Are Spreading Hallucinated npx Commands

**Source:** Aikido
**Published:** 2026-01-21
**Article:** https://www.aikido.dev/blog/agent-skills-spreading-hallucinated-npx-commands

## Threat Profile

Blog Vulnerabilities & Threats Agent Skills Are Spreading Hallucinated npx Commands Agent Skills Are Spreading Hallucinated npx Commands Written by Charlie Eriksen Published on: Jan 21, 2026 On January 14th, 2026, I claimed a package on npm called react-codeshift .
I wasn't the author. I'd never written a line of code for it. The package had never existed. No one had ever published it. And yet, 237 GitHub repositories were already referencing it, instructing AI agents to install it. Some of them…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1005** — Data from Local System
- **T1539** — Steal Web Session Cookie
- **T1555.003** — Credentials from Web Browsers
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] LLM-Hallucinated 'react-codeshift' npm Package Executed via npx/bunx/pnpm dlx/yarn dlx

`UC_466_4` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.process_name) as proc values(Processes.parent_process_name) as parent values(Processes.user) as user values(Processes.dest) as dest from datamodel=Endpoint.Processes where (Processes.process="*react-codeshift*") AND (Processes.process_name IN ("npx","npx.cmd","npx.exe","bunx","bunx.exe","pnpm","pnpm.cmd","pnpm.exe","yarn","yarn.cmd","yarn.exe","node","node.exe","bun","bun.exe") OR Processes.parent_process_name IN ("npx.exe","npx.cmd","npm.exe","npm.cmd","bunx.exe","pnpm.exe","pnpm.cmd","yarn.exe","yarn.cmd","bun.exe","node.exe")) by host Processes.dest
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "react-codeshift"
| where ProcessCommandLine has_any ("npx ","bunx ","pnpm dlx","yarn dlx","pnpx ","npx.cmd","bunx.exe")
    or InitiatingProcessFileName in~ ("npx.cmd","npx.exe","npm.cmd","npm.exe","bunx.exe","pnpm.cmd","pnpm.exe","yarn.cmd","yarn.exe","bun.exe","node.exe")
    or FileName in~ ("npx.exe","bunx.exe","pnpm.exe","yarn.exe","node.exe","bun.exe")
| extend TransformPath = extract(@"react-codeshift/transforms/([A-Za-z0-9_\-\.]+\.js)", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, TransformPath, SHA256
| order by Timestamp desc
```

### [LLM] Hallucinated 'react-codeshift' Package Files Materialised in node_modules / npx Cache

`UC_466_5` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.file_name) as file_name values(Filesystem.process_name) as proc values(Filesystem.user) as user from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\react-codeshift\\*" OR Filesystem.file_path="*\\_npx\\*react-codeshift*" OR Filesystem.file_path="*/node_modules/react-codeshift/*" OR Filesystem.file_path="*/_npx/*react-codeshift*" OR Filesystem.file_name="react-codeshift*.tgz") by host Filesystem.dest
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath has @"\node_modules\react-codeshift\"
    or FolderPath has @"/node_modules/react-codeshift/"
    or (FolderPath has @"\_npx\" and FolderPath has "react-codeshift")
    or (FolderPath has @"/_npx/" and FolderPath has "react-codeshift")
    or FileName matches regex @"(?i)^react-codeshift-\d+\.\d+\.\d+\.tgz$"
    or (FileOriginUrl has "registry.npmjs.org" and FileOriginUrl has "react-codeshift")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, FileOriginUrl, FileOriginIP, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
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

### Article-specific behavioural hunt — Agent Skills Are Spreading Hallucinated npx Commands

`UC_466_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Agent Skills Are Spreading Hallucinated npx Commands ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("unsafe-lifecycles.js","-jsx-transform.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("unsafe-lifecycles.js","-jsx-transform.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Agent Skills Are Spreading Hallucinated npx Commands
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("unsafe-lifecycles.js", "-jsx-transform.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("unsafe-lifecycles.js", "-jsx-transform.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
