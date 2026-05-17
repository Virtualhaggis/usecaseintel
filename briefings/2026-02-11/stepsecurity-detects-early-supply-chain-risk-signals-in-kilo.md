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
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Retrospective hunt: @kilocode/cli npm install during unverified-binary release window (Jan 29 – Feb 9 2026)

`UC_428_1` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","npm","node.exe","node","npx.exe","npx","yarn.exe","yarn","pnpm.exe","pnpm") AND Processes.process="*kilocode/cli*") by Processes.dest Processes.user Processes.process_name _time span=1d | `drop_dm_object_name(Processes)` | where _time >= relative_time(now(), "@d-2026-01-29") AND _time <= relative_time(now(), "@d-2026-02-15") | appendpipe [| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as path from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*node_modules*kilocode*cli*" OR Filesystem.file_path="*kilocode-cli-darwin*" OR Filesystem.file_path="*kilocode-cli-linux*" OR Filesystem.file_path="*kilocode-cli-win*") by Filesystem.dest Filesystem.user _time span=1d | `drop_dm_object_name(Filesystem)`] | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let RiskWindowStart = datetime(2026-01-29T00:00:00Z);
let RiskWindowEnd   = datetime(2026-02-15T00:00:00Z);
let NodeBins = dynamic(["npm.exe","node.exe","npx.exe","yarn.exe","pnpm.exe"]);
union isfuzzy=true
( DeviceProcessEvents
  | where Timestamp between (RiskWindowStart .. RiskWindowEnd)
  | where FileName in~ (NodeBins) or InitiatingProcessFileName in~ (NodeBins)
  | where ProcessCommandLine has "kilocode/cli"
       or ProcessCommandLine has "kilocode-cli-darwin"
       or ProcessCommandLine has "kilocode-cli-linux"
       or ProcessCommandLine has "kilocode-cli-win"
       or InitiatingProcessCommandLine has "kilocode/cli"
  | project Timestamp, DeviceName, AccountName,
            Source = "Process",
            BinName = FileName,
            CmdLine = ProcessCommandLine,
            Parent = InitiatingProcessFileName,
            ParentCmd = InitiatingProcessCommandLine,
            SHA256),
( DeviceFileEvents
  | where Timestamp between (RiskWindowStart .. RiskWindowEnd)
  | where ActionType in ("FileCreated","FileModified","FileRenamed")
  | where FolderPath has "kilocode" and (FolderPath has "node_modules" or FolderPath has @"\@kilocode\")
       or FileName startswith "kilocode-cli-"
  | project Timestamp, DeviceName,
            AccountName = InitiatingProcessAccountName,
            Source = "File",
            BinName = FileName,
            CmdLine = strcat(FolderPath, "\\", FileName),
            Parent = InitiatingProcessFileName,
            ParentCmd = InitiatingProcessCommandLine,
            SHA256)
| order by Timestamp asc
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            EventCount = count(),
            SampleCmd = any(CmdLine),
            SourcesSeen = make_set(Source),
            ParentSet = make_set(Parent)
            by DeviceName, AccountName
| order by FirstSeen asc
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
