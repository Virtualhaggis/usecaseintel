# [CRIT] Reconstructing the TJ Actions Changed Files GitHub Actions Compromise

**Source:** Snyk
**Published:** 2025-03-17
**Article:** https://snyk.io/blog/reconstructing-tj-actions-changed-files-github-actions-compromise/

## Threat Profile

Snyk Blog Written by Micah Silverman 
March 17, 2025
0 mins read In the afternoon on Friday, March 14, 2025, details began to emerge about a serious security exploit on a popular GitHub Action called changed files ( tj-actions/changed-files ). About 23,000 GitHub repos use this Action as part of their CI and DevOps workflows. It allows you to track which files have changed across branches and commits.
An attacker with write privileges on the Action repo made a commit that caused encrypted secret…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **SHA1:** `0e58ed8671d6b60d0890c21b07f8835ace038e67`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1105** — Ingress Tool Transfer
- **T1003** — OS Credential Dumping
- **T1552.001** — Credentials In Files
- **T1212** — Exploitation for Credential Access
- **T1059.004** — Unix Shell
- **T1140** — Deobfuscate/Decode Files or Information
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Self-hosted GitHub Action runner downloads memdump.py from compromised gist (CVE-2025-30066)

`UC_1001_4` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("curl","wget","curl.exe","wget.exe") AND (Processes.process="*gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965*" OR Processes.process="*memdump.py*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("curl","wget","curl.exe","wget.exe","bash","sh")
| where ProcessCommandLine has_any ("gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965","memdump.py","30e525b776c409e03c2d6f328f254965")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
```

### Runner.Worker process memory dumped via /proc/PID/mem read on Linux runner

`UC_1001_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/proc/*/mem" OR Filesystem.file_path="/proc/*/maps") AND Filesystem.process_name IN ("python","python3","python2") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.process | `drop_dm_object_name(Filesystem)` | stats values(file_path) as paths, values(process) as cmd, count by dest, user, process_name | where mvcount(paths) >= 2 OR mvfilter(match(cmd, "Runner\.Worker"))
```

**Defender KQL:**
```kql
// Memory dump primitive: python reading /proc/PID/mem (and usually /proc/PID/maps first)
let PythonProcs = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName matches regex @"^python[23]?$"
  | where ProcessCommandLine has_any ("Runner.Worker","/proc/","memdump.py","isSecret")
  | project Timestamp, DeviceId, DeviceName, AccountName, ProcessId=tostring(ProcessId), ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine;
let MemReads = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where FolderPath startswith "/proc/" and FileName in~ ("mem","maps")
  | where InitiatingProcessFileName matches regex @"^python[23]?$"
  | project Timestamp, DeviceId, DeviceName, FolderPath, FileName, InitiatingProcessId=tostring(InitiatingProcessId), InitiatingProcessCommandLine;
MemReads
| join kind=inner (PythonProcs) on DeviceId, $left.InitiatingProcessId == $right.ProcessId
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, InitiatingProcessCommandLine, ParentCmd=InitiatingProcessCommandLine1
| order by Timestamp desc
```

### Malicious tj-actions base64 payload prefix observed in process command line

`UC_1001_6` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*aWYgW1sgIiRPU1RZUEUiID09*" OR Processes.process="*\"value\":\"*\",\"isSecret\":true*" OR Processes.process="*\\\"isSecret\\\":true*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(60d)
| where ProcessCommandLine has_any (
    "aWYgW1sgIiRPU1RZUEUiID09",                       // base64 of: if [[ \"$OSTYPE\" ==
    "\"isSecret\":true",                             // grep target — secrets-pattern
    "updateFeatures",                                 // exported function name from the malicious commit
    "0e58ed8671d6b60d0890c21b07f8835ace038e67"       // confirmed malicious commit SHA (Wiz/CISA)
  )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, FolderPath
| order by Timestamp desc
```

### Git checkout of compromised tj-actions/changed-files commit on runner host

`UC_1001_7` · phase: **weapon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name IN ("git","git.exe","node","node.exe","actions-runner","Runner.Worker") AND (Processes.process="*0e58ed8671d6b60d0890c21b07f8835ace038e67*" OR Processes.process="*tj-actions/changed-files*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | eval malicious_sha=if(match(process, "0e58ed8671d6b60d0890c21b07f8835ace038e67"), "YES", "NO") | convert ctime(firstTime), ctime(lastTime)
```

**Defender KQL:**
```kql
// Two signals: (a) any git/node command line touching the malicious commit SHA, (b) any process referencing tj-actions/changed-files for inventory
DeviceProcessEvents
| where Timestamp > ago(90d)
| where ProcessCommandLine has_any (
    "0e58ed8671d6b60d0890c21b07f8835ace038e67",   // confirmed malicious commit
    "tj-actions/changed-files"                     // inventory pivot
  )
| extend Severity = iff(ProcessCommandLine has "0e58ed8671d6b60d0890c21b07f8835ace038e67", "Critical", "Informational")
| project Timestamp, Severity, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
| order by Severity asc, Timestamp desc
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

### Article-specific behavioural hunt — Reconstructing the TJ Actions Changed Files GitHub Actions Compromise

`UC_1001_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Reconstructing the TJ Actions Changed Files GitHub Actions Compromise ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/run.sh*" OR Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Reconstructing the TJ Actions Changed Files GitHub Actions Compromise
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/run.sh", "/usr/bin/env") or FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-30066`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0e58ed8671d6b60d0890c21b07f8835ace038e67`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 8 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
