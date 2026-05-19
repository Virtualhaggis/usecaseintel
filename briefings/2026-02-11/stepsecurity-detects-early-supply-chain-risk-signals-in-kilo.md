# [MED] StepSecurity Detects Early Supply Chain Risk Signals in kilocode npm

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
- **T1546.016** — Event Triggered Execution: Installer Packages

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] @kilocode/cli npm postinstall symlinking unverified platform binaries

`UC_426_1` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent_proc values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("npm.exe","npm-cli.js","node.exe","yarn.exe","pnpm.exe","npm","node","yarn","pnpm") OR Processes.process_name IN ("node.exe","node","ln","ln.exe","mklink.exe","cmd.exe","sh","bash")) (Processes.process="*@kilocode/cli*" OR Processes.process="*@kilocode/cli-darwin-arm64*" OR Processes.process="*@kilocode/cli-linux*" OR Processes.process="*@kilocode/cli-win32*") by host Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npm-cli.js","npm","node","yarn","pnpm")
    or FileName in~ ("node.exe","node","ln","mklink.exe","cmd.exe","sh","bash")
| where ProcessCommandLine has_any ("@kilocode/cli","@kilocode/cli-darwin-arm64","@kilocode/cli-linux","@kilocode/cli-win32","kilocode-cli")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
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

Severity classified as **MED** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
