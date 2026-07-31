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
- **T1059** — Command and Scripting Interpreter
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1567** — Exfiltration Over Web Service
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Nx s1ngularity: npm postinstall weaponizes AI CLI tools (claude/gemini/q) for credential recon

`UC_725_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("claude","gemini","q","claude.exe","gemini.exe","q.exe")) (Processes.process IN ("*--dangerously-skip-permissions*","*--yolo*","*--trust-all-tools*","*--no-interactive*")) (Processes.parent_process_name IN ("node","npm","npx","sh","bash","zsh","node.exe","npm.cmd","npx.cmd") OR Processes.parent_process IN ("*telemetry.js*","*postinstall*","*nx*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("claude","gemini","q","claude.exe","gemini.exe","q.exe")
| where ProcessCommandLine has_any ("--dangerously-skip-permissions","--yolo","--trust-all-tools","--no-interactive")
| where InitiatingProcessFileName in~ ("node","npm","npx","sh","bash","zsh","node.exe","npm.cmd","npx.cmd")
   or InitiatingProcessCommandLine has_any ("telemetry.js","postinstall","nx")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, SHA256
| order by Timestamp desc
```

### Nx s1ngularity exfiltration via public GitHub repo 's1ngularity-repository'

`UC_725_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*s1ngularity-repository*" OR Processes.parent_process="*s1ngularity-repository*" OR Processes.process="*/tmp/inventory.txt*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("s1ngularity-repository","/tmp/inventory.txt")
   or InitiatingProcessCommandLine has "s1ngularity-repository"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### tj-actions/changed-files: CI runner pipes gist memdump.py to python to scrape secrets

`UC_725_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*memdump.py*" OR Processes.process="*gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965*" OR Processes.process="*0e58ed8671d6b60d0890c21b07f8835ace038e67*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where ProcessCommandLine has_any ("memdump.py",
        "gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965",
        "0e58ed8671d6b60d0890c21b07f8835ace038e67")
   or (ProcessCommandLine has "gist.githubusercontent.com" and ProcessCommandLine has "memdump.py")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
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

Severity classified as **HIGH** based on: 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
