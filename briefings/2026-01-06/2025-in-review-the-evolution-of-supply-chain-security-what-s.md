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
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1592** — Gather Victim Host Information
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1567** — Exfiltration Over Web Service
- **T1567.001** — Exfiltration to Code Repository
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1140** — Deobfuscate/Decode Files or Information
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Nx s1ngularity — Node/npm spawning AI CLI tools (claude/gemini/q) for recon

`UC_501_1` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.process_path) as image_paths from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","node.exe","npm","npm.exe","npm-cli.js","npx","npx.exe","yarn","yarn.exe","pnpm","pnpm.exe")) AND (Processes.process_name IN ("claude","claude.exe","gemini","gemini.exe","q","q.exe","amazon-q","amazon-q.exe") OR Processes.process IN ("*claude *","*gemini *","*amazon-q *","* q chat *","* q run *")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName !endswith "$"
| where InitiatingProcessFileName in~ ("node.exe","node","npm.exe","npm","npx.exe","npx","yarn.exe","yarn","pnpm.exe","pnpm")
| where FileName in~ ("claude.exe","claude","gemini.exe","gemini","q.exe","q","amazon-q.exe","amazon-q")
   or ProcessCommandLine matches regex @"(?i)(^|[\\/])(claude|gemini|amazon-q)(\.exe)?\b"
   or ProcessCommandLine matches regex @"(?i)\bq\s+(chat|run|translate|ask)\b"
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          ChildSHA256 = SHA256
| order by Timestamp desc
```

### [LLM] Nx s1ngularity — 's1ngularity-repository' exfil string in process / git activity

`UC_501_2` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process) as parents from datamodel=Endpoint.Processes where (Processes.process="*s1ngularity-repository*" OR Processes.parent_process="*s1ngularity-repository*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | append [| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.file_path="*s1ngularity-repository*" by Filesystem.dest Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)`]
```

**Defender KQL:**
```kql
let WindowDays = 60d;
let exfil_token = "s1ngularity-repository";
union isfuzzy=true
  (DeviceProcessEvents
   | where Timestamp > ago(WindowDays)
   | where AccountName !endswith "$"
   | where ProcessCommandLine has exfil_token
      or InitiatingProcessCommandLine has exfil_token
   | project Timestamp, Source = "Process", DeviceName, AccountName,
             FileName, ProcessCommandLine,
             InitiatingProcessFileName, InitiatingProcessCommandLine,
             SHA256),
  (DeviceFileEvents
   | where Timestamp > ago(WindowDays)
   | where FolderPath has exfil_token or FileName has exfil_token
   | project Timestamp, Source = "File", DeviceName,
             AccountName = InitiatingProcessAccountName,
             FileName, ProcessCommandLine = InitiatingProcessCommandLine,
             InitiatingProcessFileName, InitiatingProcessCommandLine,
             SHA256),
  (DeviceNetworkEvents
   | where Timestamp > ago(WindowDays)
   | where RemoteUrl has "api.github.com"
   | where InitiatingProcessCommandLine has exfil_token
   | project Timestamp, Source = "Net", DeviceName,
             AccountName = InitiatingProcessAccountName,
             FileName = InitiatingProcessFileName, ProcessCommandLine = InitiatingProcessCommandLine,
             InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256 = InitiatingProcessSHA256)
| order by Timestamp desc
```

### [LLM] tj-actions/changed-files compromise — curl to gist.githubusercontent.com from CI runner context

`UC_501_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process) as parents values(Processes.parent_process_name) as parent_names from datamodel=Endpoint.Processes where (Processes.process_name IN ("curl","curl.exe","wget","wget.exe")) AND Processes.process="*gist.githubusercontent.com*" AND (Processes.parent_process_name IN ("Runner.Worker.exe","Runner.Listener.exe","Runner.Worker","Runner.Listener","runsvc.sh","bash","sh","node","node.exe","powershell.exe","pwsh.exe") OR Processes.parent_process="*_work/_actions*" OR Processes.parent_process="*actions-runner*" OR Processes.parent_process="*tj-actions*" OR Processes.parent_process="*changed-files*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl.exe","curl","wget.exe","wget")
| where ProcessCommandLine has "gist.githubusercontent.com"
| where InitiatingProcessFileName in~ ("Runner.Worker.exe","Runner.Listener.exe","Runner.Worker","Runner.Listener","runsvc.sh","bash","sh","dash","node.exe","node","pwsh.exe","powershell.exe")
   or InitiatingProcessCommandLine has_any ("actions-runner","_work/_actions","tj-actions","changed-files")
   or InitiatingProcessFolderPath has_any (@"\actions-runner\",@"/actions-runner/",@"/_work/_actions/")
| extend B64Pipe = iff(ProcessCommandLine has_any ("base64 -d","base64 --decode","| base64"), "yes", "no")
| project Timestamp, DeviceName, AccountName,
          ParentImage = InitiatingProcessFolderPath,
          ParentCmd   = InitiatingProcessCommandLine,
          ChildImage  = FolderPath,
          ChildCmd    = ProcessCommandLine,
          B64Pipe, SHA256
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

Severity classified as **HIGH** based on: 4 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
