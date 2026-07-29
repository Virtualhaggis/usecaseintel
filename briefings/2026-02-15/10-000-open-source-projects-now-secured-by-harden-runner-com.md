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
- **T1528** — Steal Application Access Token
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1546.004** — Event Triggered Execution: Unix Shell Configuration Modification
- **T1529** — System Shutdown/Reboot

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### npm/node post-install (telemetry.js) spawning credential CLIs (gh auth token / npm whoami) — s1ngularity Nx

`UC_639_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node","node.exe","npm","npm.cmd","sh","bash","zsh") AND (Processes.process="*gh auth token*" OR Processes.process="*npm whoami*") by Processes.dest Processes.user Processes.parent_process Processes.parent_process_name Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node","node.exe","npm","npm.cmd","sh","bash","zsh")
| where (FileName in~ ("gh","gh.exe") and ProcessCommandLine has "auth token")
     or (FileName in~ ("npm","npm.cmd") and ProcessCommandLine has "whoami")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Local AI coding agents (claude/gemini/q) launched with permission-bypass flags during package install — s1ngularity

`UC_639_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("claude","gemini","q","claude.exe","gemini.exe","q.exe") AND (Processes.process="*--dangerously-skip-permissions*" OR Processes.process="*--yolo*" OR Processes.process="*--trust-all-tools*") by Processes.dest Processes.user Processes.parent_process Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("claude","claude.exe","gemini","gemini.exe","q","q.exe")
| where ProcessCommandLine has_any ("--dangerously-skip-permissions","--yolo","--trust-all-tools")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          ParentProcess = InitiatingProcessFileName,
          ParentCmd = InitiatingProcessCommandLine,
          Child = FileName,
          ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Shell rc files (.bashrc/.zshrc) modified by package-install process — s1ngularity persistence/shutdown

`UC_639_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.action IN ("modified","created","write") AND Filesystem.file_name IN (".bashrc",".zshrc",".bash_profile",".profile",".zprofile") AND Filesystem.process_name IN ("node","node.exe","npm","npm.cmd","sh","bash","zsh") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileModified","FileCreated","FileRenamed")
| where FileName in~ (".bashrc",".zshrc",".bash_profile",".profile",".zprofile")
| where InitiatingProcessFileName in~ ("node","node.exe","npm","npm.cmd","sh","bash","zsh")
   or InitiatingProcessCommandLine has_any ("telemetry.js","postinstall","npm install","npm ci")
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, FolderPath, ActionType
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

Severity classified as **HIGH** based on: 4 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
