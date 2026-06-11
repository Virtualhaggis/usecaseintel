# [HIGH] StepSecurity Detects Early Supply Chain Risk Signals in kilocode npm

**Source:** StepSecurity
**Published:** 2026-02-11
**Article:** https://www.stepsecurity.io/blog/stepsecurity-detects-early-supply-chain-risk-signals-in-kilocode-npm

## Threat Profile

Back to Blog Threat Intel StepSecurity Detects Early Supply Chain Risk Signals in kilocode npm StepSecurity detected early supply chain risk signals in a legitimate kilocode npm release, showing how small behavior changes can quietly weaken trust before attacks happen Sai Likhith View LinkedIn February 9, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Supply chain security stories often focus on confirmed compromises. But man…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1554** — Compromise Host Software Binary
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Inventory: @kilocode/cli v1.0.0-v1.0.3 affected-release install on dev workstations

`UC_544_1` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("npm.exe","npm.cmd","node.exe","yarn.cmd","pnpm.cmd") OR Processes.process_name IN ("node.exe","node")) AND (Processes.process="*@kilocode/cli*" OR Processes.parent_process="*@kilocode/cli*" OR Processes.process="*node_modules\\@kilocode\\cli*" OR Processes.process="*node_modules/@kilocode/cli*") by host Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where InitiatingProcessFileName in~ ("node.exe","node","npm.cmd","npm.exe","yarn.cmd","pnpm.cmd") or FileName in~ ("node.exe","node")
| where ProcessCommandLine has "@kilocode/cli" 
    or InitiatingProcessCommandLine has "@kilocode/cli"
    or FolderPath has @"\node_modules\@kilocode\cli"
    or InitiatingProcessFolderPath has @"\node_modules\@kilocode\cli"
    or ProcessCommandLine has "node_modules/@kilocode/cli"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          SHA256
| order by Timestamp desc
```

### npm postinstall: @kilocode/cli platform-binary directory (cli-{platform}-{arch}) write

`UC_544_2` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("created","modified") AND (Filesystem.file_path="*node_modules\\@kilocode\\cli-darwin-arm64*" OR Filesystem.file_path="*node_modules\\@kilocode\\cli-darwin-x64*" OR Filesystem.file_path="*node_modules\\@kilocode\\cli-linux-x64*" OR Filesystem.file_path="*node_modules\\@kilocode\\cli-linux-arm64*" OR Filesystem.file_path="*node_modules\\@kilocode\\cli-win32-x64*" OR Filesystem.file_path="*node_modules/@kilocode/cli-darwin-arm64*" OR Filesystem.file_path="*node_modules/@kilocode/cli-linux-x64*" OR Filesystem.file_path="*node_modules/@kilocode/cli-win32-x64*") by host Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(60d)
| where ActionType in ("FileCreated","FileRenamed","FileModified")
| where FolderPath matches regex @"(?i)\\node_modules\\@kilocode\\cli-(darwin|linux|win32|win64)-(arm64|x64|x86|ia32)\\"
    or FolderPath matches regex @"(?i)/node_modules/@kilocode/cli-(darwin|linux|win32|win64)-(arm64|x64|x86|ia32)/"
| where InitiatingProcessFileName in~ ("node.exe","node","npm.cmd","npm.exe","yarn.cmd","pnpm.cmd")
| project Timestamp, DeviceName, AccountName = InitiatingProcessAccountName,
          FolderPath, FileName, FileSize,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### npm/yarn/pnpm postinstall: Node child egressing to non-registry public host

`UC_544_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.dest_port) as dest_port values(All_Traffic.app) as remote_host from datamodel=Network_Traffic.All_Traffic where All_Traffic.process_name IN ("node.exe","node") AND All_Traffic.dest_category="public" by host All_Traffic.src All_Traffic.user All_Traffic.process_name All_Traffic.process | `drop_dm_object_name(All_Traffic)` | search NOT (remote_host="*.npmjs.org" OR remote_host="*.npmjs.com" OR remote_host="*.yarnpkg.com" OR remote_host="*.nodejs.org" OR remote_host="*.github.com" OR remote_host="*.githubusercontent.com" OR remote_host="*.jsdelivr.net" OR remote_host="*.unpkg.com") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let RegistryAllowlist = dynamic(["registry.npmjs.org","npmjs.com","www.npmjs.com","registry.yarnpkg.com","yarnpkg.com","nodejs.org","github.com","objects.githubusercontent.com","raw.githubusercontent.com","codeload.github.com","cdn.jsdelivr.net","unpkg.com"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where InitiatingProcessParentFileName in~ ("npm.cmd","npm.exe","yarn.cmd","pnpm.cmd","node.exe")
   or InitiatingProcessCommandLine has_any ("postinstall","preinstall","install.js","install.cjs","install.mjs","node_modules")
| where RemoteIPType == "Public"
| extend HostOnly = tolower(tostring(parse_url(strcat("https://", RemoteUrl)).Host))
| where isnotempty(RemoteUrl)
| where not(RemoteUrl has_any (RegistryAllowlist))
| where InitiatingProcessAccountName !endswith "$"
| summarize FirstSeen = min(Timestamp), Hits = count(), SampleHosts = make_set(RemoteUrl, 10), SampleIPs = make_set(RemoteIP, 10), SampleCmd = any(InitiatingProcessCommandLine)
            by DeviceName, InitiatingProcessAccountName, InitiatingProcessParentFileName
| order by FirstSeen desc
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

Severity classified as **HIGH** based on: 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
