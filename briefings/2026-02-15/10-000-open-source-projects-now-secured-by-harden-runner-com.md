# [HIGH] 10,000 Open-Source Projects Now Secured by Harden-Runner Community-Tier: A Milestone Three Years in the Making

**Source:** StepSecurity
**Published:** 2026-02-15
**Article:** https://www.stepsecurity.io/blog/10-000-open-source-projects-now-secured-by-harden-runner-community-tier-a-milestone-three-years-in-the-making

## Threat Profile

Back to Blog Threat Intel 10,000 Open-Source Projects Now Secured by Harden-Runner Community-Tier: A Milestone Three Years in the Making From 5,000 to 10,000 in just one year: How Harden-Runner doubled its reach and became the standard for CI/CD runtime security Eromosele Akhigbe View LinkedIn January 8, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
At StepSecurity, we set out to solve a fundamental problem
CI/CD pipelines h…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1059** — Command and Scripting Interpreter
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1083** — File and Directory Discovery
- **T1567** — Exfiltration Over Web Service
- **T1213.003** — Data from Information Repositories: Code Repositories
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1555** — Credentials from Password Stores
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] s1ngularity Nx postinstall: AI CLI weaponization (claude/gemini/q) with permission-bypass flags

`UC_411_1` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node.exe","node","npm.exe","npm","npm.cmd","npx.exe","npx","yarn.exe","yarn","yarn.cmd","pnpm.exe","pnpm","pnpm.cmd") AND ( (Processes.process_name IN ("claude","claude.exe","claude.cmd") AND Processes.process="*--dangerously-skip-permissions*") OR (Processes.process_name IN ("gemini","gemini.exe","gemini.cmd") AND Processes.process="*--yolo*") OR (Processes.process_name IN ("q","q.exe") AND Processes.process="*--trust-all-tools*") ) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where user!="*$"
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm","npm.cmd","npx.exe","npx","yarn.exe","yarn","yarn.cmd","pnpm.exe","pnpm","pnpm.cmd")
   or InitiatingProcessParentFileName in~ ("node.exe","node","npm.exe","npm","npm.cmd","npx.exe","npx","yarn.exe","yarn","pnpm.exe","pnpm")
| where (FileName in~ ("claude","claude.exe","claude.cmd") and ProcessCommandLine has "--dangerously-skip-permissions")
     or (FileName in~ ("gemini","gemini.exe","gemini.cmd") and ProcessCommandLine has "--yolo")
     or (FileName in~ ("q","q.exe") and ProcessCommandLine has "--trust-all-tools")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### [LLM] s1ngularity exfiltration: gh CLI creating public repo matching s1ngularity-repository-* pattern

`UC_411_2` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.process_name IN ("gh","gh.exe") AND Processes.process="*s1ngularity-repository*" by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | where user!="*$"
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where AccountName !endswith "$"
| where FileName in~ ("gh","gh.exe")
| where ProcessCommandLine matches regex @"(?i)s1ngularity-repository(-[a-z0-9]{4,6})?"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### [LLM] Compromised npm/yarn post-install spawning gh auth token (s1ngularity credential harvest)

`UC_411_3` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines from datamodel=Endpoint.Processes where Processes.process_name IN ("gh","gh.exe") AND Processes.process="*auth token*" AND Processes.parent_process_name IN ("node","node.exe","npm","npm.exe","npm.cmd","npx","npx.exe","yarn","yarn.exe","yarn.cmd","pnpm","pnpm.exe","pnpm.cmd","sh","bash","dash","zsh") by Processes.dest Processes.user Processes.process Processes.parent_process Processes.parent_process_name | `drop_dm_object_name(Processes)` | where user!="*$" AND (parent_process LIKE "%npm%" OR parent_process LIKE "%yarn%" OR parent_process LIKE "%pnpm%" OR parent_process LIKE "%postinstall%" OR parent_process LIKE "%node_modules%")
```

**Defender KQL:**
```kql
let _pkg_managers = dynamic(["node","node.exe","npm","npm.exe","npm.cmd","npx","npx.exe","yarn","yarn.exe","yarn.cmd","pnpm","pnpm.exe","pnpm.cmd"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where FileName in~ ("gh","gh.exe")
| where ProcessCommandLine matches regex @"(?i)\bauth\s+token\b"
| where InitiatingProcessFileName in~ (_pkg_managers)
   or InitiatingProcessParentFileName in~ (_pkg_managers)
   or InitiatingProcessCommandLine has_any ("postinstall", "node_modules", "npm-cli", "yarn run", "pnpm run")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, InitiatingProcessFolderPath, SHA256
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


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
