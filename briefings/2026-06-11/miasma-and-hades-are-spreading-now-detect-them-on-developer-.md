# [HIGH] Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspicious Files

**Source:** StepSecurity
**Published:** 2026-06-11
**Article:** https://www.stepsecurity.io/blog/miasma-and-hades-are-spreading-now-detect-them-on-developer-machines-with-suspicious-files

## Threat Profile

Back to Blog Product Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspicious Files Miasma and Hades worms are spreading across npm and PyPI, running on import and project open. See how Dev Machine Guard's Suspicious Files detects them. Ashish Kurmi View LinkedIn June 11, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
The Miasma worm and its PyPI branch, Hades, are spreading across the npm and PyP…

## Indicators of Compromise (high-fidelity only)

- **SHA256:** `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe`
- **SHA256:** `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d`
- **SHA256:** `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c`
- **SHA256:** `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655`
- **SHA256:** `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966`

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1546** — Event Triggered Execution
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer
- **T1552** — Unsecured Credentials
- **T1059** — Command and Scripting Interpreter
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1567** — Exfiltration Over Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma/Hades dev-tool config dropped by non-IDE process (.claude/.cursor/.vscode/.gemini/.github)

`UC_8_4` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as first_seen max(_time) as last_seen values(Filesystem.process_path) as proc_paths values(Filesystem.file_hash) as hashes from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified","renamed") AND (Filesystem.file_path="*\\.claude\\setup.mjs" OR Filesystem.file_path="*\\.claude\\settings.json" OR Filesystem.file_path="*\\.cursor\\rules\\setup.mdc" OR Filesystem.file_path="*\\.gemini\\settings.json" OR Filesystem.file_path="*\\.vscode\\tasks.json" OR Filesystem.file_path="*\\.vscode\\setup.mjs" OR Filesystem.file_path="*\\.github\\setup.js") AND Filesystem.process_name IN ("node.exe","npm.exe","npx.cmd","python.exe","python3.exe","pip.exe","pip3.exe","bun.exe","git.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","curl.exe","wget.exe") by host Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name | `drop_dm_object_name(Filesystem)` | where NOT match(user,"\$$")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where (FolderPath has @"\.claude\" and FileName in~ ("setup.mjs","settings.json"))
   or  (FolderPath has @"\.cursor\rules\" and FileName =~ "setup.mdc")
   or  (FolderPath has @"\.gemini\" and FileName =~ "settings.json")
   or  (FolderPath has @"\.vscode\" and FileName in~ ("tasks.json","setup.mjs"))
   or  (FolderPath has @"\.github\" and FileName =~ "setup.js")
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","npx.cmd","python.exe","python3.exe","pip.exe","pip3.exe","bun.exe","git.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","curl.exe","wget.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, FileName, FolderPath, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Phantom Gyp - tiny binding.gyp dropped into node_modules during npm install

`UC_8_5` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as first_seen max(_time) as last_seen values(Filesystem.process_name) as procs values(Filesystem.file_hash) as hashes from datamodel=Endpoint.Filesystem where Filesystem.file_name="binding.gyp" AND Filesystem.action IN ("created","modified") AND Filesystem.file_size>=100 AND Filesystem.file_size<=400 AND (Filesystem.file_path="*\\node_modules\\*" OR Filesystem.file_path="*\\AppData\\Roaming\\npm\\*" OR Filesystem.file_path="*\\.npm\\*") by host Filesystem.user Filesystem.file_path Filesystem.file_size Filesystem.process_name | `drop_dm_object_name(Filesystem)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified")
| where FileName =~ "binding.gyp"
| where FileSize between (100 .. 400)   // article: 157-byte payload
| where FolderPath has_any (@"\node_modules\", @"\AppData\Roaming\npm\", @"\.npm\")
   or InitiatingProcessFileName in~ ("npm.exe","npm.cmd","node.exe","npx.cmd","yarn.exe","pnpm.exe")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, FolderPath, FileName, FileSize, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessAccountName
| order by Timestamp desc
```

### Hades on-import: python.exe spawns bun.exe / downloads Bun runtime from oven-sh

`UC_8_6` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.process_name="bun.exe" AND Processes.parent_process_name IN ("python.exe","python3.exe","python3.11.exe","python3.12.exe","python3.13.exe","pip.exe","pip3.exe","node.exe","powershell.exe","pwsh.exe","cmd.exe") by host Processes.user Processes.parent_process_name Processes.process Processes.process_path Processes.parent_process _time | `drop_dm_object_name(Processes)` | rename _time as proc_time | join type=inner host [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where (Network_Traffic.dest="bun.sh" OR Network_Traffic.dest="registry.bun.sh" OR Network_Traffic.url="*github.com/oven-sh/bun*" OR Network_Traffic.url="*bun-windows-x64*") AND Network_Traffic.process_name IN ("python.exe","python3.exe","pip.exe","curl.exe","powershell.exe","pwsh.exe","wget.exe") by host _time | rename _time as net_time | fields host net_time] | where proc_time >= net_time AND proc_time <= net_time + 300
```

**Defender KQL:**
```kql
let BunDownloads = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any ("bun.sh","github.com/oven-sh/bun","registry.bun.sh","bun-windows-x64","bun-linux-x64","bun-darwin-x64")
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","python3.11.exe","python3.12.exe","python3.13.exe","pip.exe","pip3.exe","curl.exe","powershell.exe","pwsh.exe","wget.exe")
    | project NetTime = Timestamp, DeviceName, RemoteUrl, RemoteIP, NetProc = InitiatingProcessFileName, NetCmd = InitiatingProcessCommandLine;
let BunSpawn = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName =~ "bun.exe" or FolderPath endswith @"\bun.exe"
    | where InitiatingProcessFileName in~ ("python.exe","python3.exe","python3.11.exe","python3.12.exe","python3.13.exe","pip.exe","node.exe","powershell.exe","pwsh.exe","cmd.exe")
    | project ProcTime = Timestamp, DeviceName, BunPath = FolderPath, BunCmd = ProcessCommandLine, Parent = InitiatingProcessFileName, ParentCmd = InitiatingProcessCommandLine, SHA256, AccountName;
BunDownloads
| join kind=inner BunSpawn on DeviceName
| where ProcTime between (NetTime .. NetTime + 5m)
| where AccountName !endswith "$"
| project NetTime, ProcTime, DelaySec = datetime_diff('second', ProcTime, NetTime), DeviceName, AccountName, RemoteUrl, NetProc, NetCmd, BunPath, BunCmd, Parent, ParentCmd, SHA256
| order by ProcTime desc
```

### IDE auto-load: VSCode/Cursor/Claude/Gemini spawns scripting host referencing Miasma persistence config

`UC_8_7` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as first_seen max(_time) as last_seen values(Processes.process) as cmds values(Processes.process_hash) as hashes from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("Code.exe","Code - Insiders.exe","Cursor.exe","claude.exe","claude-code.exe","gemini.exe") AND Processes.process_name IN ("node.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","bun.exe","bash.exe","python.exe","sh.exe") AND (Processes.process="*\\.vscode\\tasks.json*" OR Processes.process="*\\.vscode\\setup.mjs*" OR Processes.process="*\\.claude\\setup.mjs*" OR Processes.process="*\\.claude\\settings.json*" OR Processes.process="*\\.cursor\\rules\\setup.mdc*" OR Processes.process="*\\.gemini\\settings.json*" OR Processes.process="*\\.github\\setup.js*" OR Processes.process="*setup.mjs*" OR Processes.process="*setup.mdc*") by host Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("Code.exe","Code - Insiders.exe","Cursor.exe","claude.exe","claude-code.exe","gemini.exe")
| where FileName in~ ("node.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","bun.exe","bash.exe","python.exe","sh.exe")
| where ProcessCommandLine has_any (".vscode\\tasks.json",".vscode\\setup.mjs",".claude\\setup.mjs",".claude\\settings.json",".cursor\\rules\\setup.mdc",".gemini\\settings.json",".github\\setup.js")
   or ProcessCommandLine matches regex @"(?i)setup\.(mjs|mdc|js)"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Worm self-propagation: burst of npm publish / git push from a single developer host

`UC_8_8` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Processes.process) as cmds values(Processes.process_path) as paths min(_time) as first_seen max(_time) as last_seen from datamodel=Endpoint.Processes where ((Processes.process_name IN ("npm.exe","npm.cmd") AND Processes.process="*publish*") OR (Processes.process_name="git.exe" AND Processes.process="*push*")) by host Processes.user Processes.process_name span=10m | `drop_dm_object_name(Processes)` | where count >= 5 AND NOT match(user,"\$$") AND NOT match(host,"(?i)^(ci-|build-|runner-|agent-|gh-runner)")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName in~ ("npm.exe","npm.cmd") and ProcessCommandLine has "publish")
   or  (FileName =~ "git.exe" and ProcessCommandLine has "push" and not(ProcessCommandLine has_any ("--dry-run","--help")))
| where AccountName !endswith "$"
| where DeviceName !startswith "ci-" and DeviceName !startswith "build-" and DeviceName !startswith "runner-" and DeviceName !startswith "gh-runner"
| summarize ActionCount = count(),
            DistinctCmds = dcount(ProcessCommandLine),
            SampleCmds = make_set(ProcessCommandLine, 20),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            WindowSec = datetime_diff('second', max(Timestamp), min(Timestamp))
            by DeviceName, AccountName, FileName, bin(Timestamp, 10m)
| where (FileName in~ ("npm.exe","npm.cmd") and ActionCount >= 5)
     or (FileName =~ "git.exe" and ActionCount >= 10)
| order by ActionCount desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspi

`UC_8_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspi ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("__init__.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("__init__.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Miasma and Hades Are Spreading Now: Detect Them on Developer Machines with Suspi
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("__init__.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("__init__.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe`, `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d`, `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c`, `7069e28a5806db4ab0273639667d203f5e31b401d403af7e36d9f360c1f6d655`, `b86c5ae9e95bd841a595440faa3eb6317441e746f241ae8fd641ab59ed1d1966`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 9 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
