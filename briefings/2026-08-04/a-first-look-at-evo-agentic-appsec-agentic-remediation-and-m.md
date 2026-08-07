# [HIGH] A First Look at Evo Agentic AppSec: Agentic Remediation and Malicious Code Defense

**Source:** Snyk
**Published:** 2026-08-04
**Article:** https://snyk.io/blog/remediation-agent-malicious-code-defense/

## Threat Profile

Snyk Blog In this article
Written by Brendan Hann 
August 4, 2026
0 mins read The Remediation Agent and Malicious Code Defense are the first two pieces of Evo Agentic AppSec: security that not only surfaces risk, but resolves it and prevents the next ones. 
This morning, we announced the broadest expansion of the Snyk AI Security Platform to date: discover, remediate, validate, and prevent. A loop with a missing segment is not a loop; it is a gap that an autonomous attacker will occupy. Evo Cont…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`
- **SHA256:** `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`
- **SHA256:** `d584f9b6af48b7ed1f93713944f033783bf149e1c25e1643eb8c0e9df5dc7782`

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1528** — Steal Application Access Token
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm preinstall hook executing setup.mjs / Math_Symbol.js (keyv/cacheable worm)

`UC_81_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where ((Processes.parent_process_name IN ("npm.exe","npm-cli.js","node.exe","npm","node","corepack.exe","yarn.exe","pnpm.exe") AND (Processes.process="*setup.mjs*" OR Processes.process="*Math_Symbol.js*")) OR (Processes.process_hash IN ("54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668","9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc","d584f9b6af48b7ed1f93713944f033783bf149e1c25e1643eb8c0e9df5dc7782"))) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_hash | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessFileName in~ ("npm.exe","node.exe","npm","node","corepack.exe","yarn.exe","pnpm.exe","npm-cli.js") and (ProcessCommandLine has "setup.mjs" or ProcessCommandLine has "Math_Symbol.js"))
    or SHA256 in ("54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668","9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc","d584f9b6af48b7ed1f93713944f033783bf149e1c25e1643eb8c0e9df5dc7782")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### keyv worm loader pulling Bun 1.3.13 runtime from GitHub during install

`UC_81_3` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.url="*github*" AND (Web.url="*oven-sh/bun*" OR Web.url="*bun-v1.3.13*" OR Web.url="*bun-linux*" OR Web.url="*bun-darwin*" OR Web.url="*bun-windows*")) by Web.src Web.dest Web.url Web.http_user_agent Web.user | `drop_dm_object_name(Web)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm","bun.exe","bun")
| where RemoteUrl has_any ("oven-sh/bun","bun-v1.3.13","githubusercontent.com") or RemoteUrl endswith "github.com"
| where InitiatingProcessCommandLine has_any ("setup.mjs","Math_Symbol.js","preinstall") or InitiatingProcessParentFileName in~ ("npm.exe","npm","node.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### npm-install child process reading developer credential stores (keyv stealer)

`UC_81_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path IN ("*/.npmrc","*\\.npmrc","*/.aws/credentials","*\\.aws\\credentials","*/.config/gh/hosts.yml","*/.kube/config","*\\.kube\\config","*/.vault-token")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node.exe","node","bun.exe","bun","npm.exe","npm")
| where FolderPath has_any (".npmrc","\\.aws\\","/.aws/","hosts.yml","\\.kube\\","/.kube/",".vault-token")
| where InitiatingProcessCommandLine has_any ("setup.mjs","Math_Symbol.js","preinstall") or InitiatingProcessParentFileName in~ ("npm.exe","npm","node.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName
| order by Timestamp desc
```

### keyv worm planting .claude / .vscode auto-run hooks in project (agentic dev target)

`UC_81_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where ((Filesystem.file_path IN ("*/.claude/*","*\\.claude\\*","*/.vscode/*","*\\.vscode\\*")) AND Filesystem.file_name IN ("settings.json","settings.local.json","tasks.json","mcp.json","hooks.json") AND Filesystem.action IN ("created","modified","write")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has_any ("\\.claude\\","/.claude/","\\.vscode\\","/.vscode/")
| where FileName in~ ("settings.json","settings.local.json","tasks.json","mcp.json","hooks.json")
| where InitiatingProcessFileName in~ ("node.exe","node","bun.exe","bun","npm.exe","npm")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FolderPath, FileName
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

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668`, `9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc`, `d584f9b6af48b7ed1f93713944f033783bf149e1c25e1643eb8c0e9df5dc7782`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
