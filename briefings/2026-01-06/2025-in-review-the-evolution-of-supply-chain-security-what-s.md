# [HIGH] 2025 in Review: The Evolution of Supply Chain Security & What's Next

**Source:** StepSecurity
**Published:** 2026-01-06
**Article:** https://www.stepsecurity.io/blog/2025-in-review-the-evolution-of-supply-chain-security-whats-next

## Threat Profile

Back to Blog Product 2025 in Review: The Evolution of Supply Chain Security & What's Next How StepSecurity achieved 5X ARR growth for the second year in a row while securing over 10,000 open-source repositories in 2025 Varun Sharma View LinkedIn January 6, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
StepSecurity detected some of the most consequential supply chain attacks of 2025, often before they were publicly known. Tod…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1078** — Valid Accounts
- **T1567.002** — Exfiltration to Cloud Storage
- **T1059** — Command and Scripting Interpreter
- **T1083** — File and Directory Discovery
- **T1552.001** — Credentials in Files
- **T1546.016** — Installer Packages

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### tj-actions/changed-files compromised commit SHA referenced in workflow YAML or git history

`UC_645_1` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*0e58ed8671d6b60d0890c21b07f8835ace038e67*" OR (Processes.process="*tj-actions/changed-files*" AND Processes.process="*@0e58ed*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where ProcessCommandLine has "0e58ed8671d6b60d0890c21b07f8835ace038e67"
   or (ProcessCommandLine has "tj-actions/changed-files" and ProcessCommandLine has "@0e58ed")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Nx s1ngularity-repository creation via GitHub API from developer or CI endpoint

`UC_645_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="results.b64" OR Filesystem.file_name="telemetry.js") AND (Filesystem.process_name="node.exe" OR Filesystem.process_name="node" OR Filesystem.process_name="npm.exe" OR Filesystem.process_name="npm") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let SuspiciousFiles = dynamic(["results.b64","telemetry.js"]);
let NodeBins = dynamic(["node.exe","node","npm.exe","npm","npx.exe","npx","pnpm.exe","pnpm","yarn.exe","yarn"]);
DeviceFileEvents
| where Timestamp > ago(180d)
| where FileName in~ (SuspiciousFiles)
| where InitiatingProcessFileName in~ (NodeBins)
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### AI CLI tool (claude/gemini/q) spawned non-interactively by node/npm/npx for recon

`UC_645_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="claude" OR Processes.process_name="claude.exe" OR Processes.process_name="gemini" OR Processes.process_name="gemini.exe" OR Processes.process_name="q" OR Processes.process_name="q.exe") AND (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node" OR Processes.parent_process_name="npm.exe" OR Processes.parent_process_name="npm" OR Processes.parent_process_name="npx.exe" OR Processes.parent_process_name="npx" OR Processes.parent_process_name="pnpm.exe" OR Processes.parent_process_name="yarn.exe") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let AiCli = dynamic(["claude","claude.exe","gemini","gemini.exe","q","q.exe"]);
let NodeParents = dynamic(["node.exe","node","npm.exe","npm","npx.exe","npx","pnpm.exe","pnpm","yarn.exe","yarn"]);
DeviceProcessEvents
| where Timestamp > ago(90d)
| where FileName in~ (AiCli)
| where InitiatingProcessFileName in~ (NodeParents)
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

### Compromised Nx npm package version install on developer or CI host

`UC_645_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="npm.exe" OR Processes.process_name="npm" OR Processes.process_name="npx.exe" OR Processes.process_name="npx" OR Processes.process_name="yarn.exe" OR Processes.process_name="pnpm.exe") AND (Processes.process="*nx@20.9*" OR Processes.process="*nx@20.10*" OR Processes.process="*nx@20.11*" OR Processes.process="*nx@20.12*" OR Processes.process="*nx@21.5*" OR Processes.process="*nx@21.6*" OR Processes.process="*nx@21.7*" OR Processes.process="*nx@21.8*" OR Processes.process="*@nx/enterprise-cloud@3.2.0*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
let CompromisedRefs = dynamic(["nx@20.9","nx@20.10","nx@20.11","nx@20.12","nx@21.5","nx@21.6","nx@21.7","nx@21.8","@nx/enterprise-cloud@3.2.0"]);
let NodePkgMgrs = dynamic(["npm.exe","npm","npx.exe","npx","yarn.exe","yarn","pnpm.exe","pnpm"]);
DeviceProcessEvents
| where Timestamp > ago(365d)
| where FileName in~ (NodePkgMgrs)
| where ProcessCommandLine has_any (CompromisedRefs)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
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

Severity classified as **HIGH** based on: 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
