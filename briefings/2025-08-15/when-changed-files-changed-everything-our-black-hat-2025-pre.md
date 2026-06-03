# [CRIT] When 'Changed Files' Changed Everything: Our Black Hat 2025 Presentation on the tj-actions Supply Chain Breach

**Source:** StepSecurity
**Published:** 2025-08-15
**Article:** https://www.stepsecurity.io/blog/when-changed-files-changed-everything-our-black-hat-2025-presentation-on-the-tj-actions-supply-chain-breach

## Threat Profile

Back to Blog Threat Intel When 'Changed Files' Changed Everything: Our Black Hat 2025 Presentation on the tj-actions Supply Chain Breach We reveal how baseline-driven monitoring caught one of 2025's most consequential CI/CD supply chain attacks, exposing the vulnerability of 23,000+ repositories including those from GitHub, Meta, and Microsoft. Ashish Kurmi View LinkedIn August 12, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav..…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **CVE:** `CVE-2025-30154`
- **SHA1:** `0e58ed8671d6b60d0890c21b07f8835ace038e67`
- **SHA1:** `6e6023c01918b353229af0881232f601a4cc8365`
- **SHA1:** `fbc2c5ebe64389f297a7808025379f77133f1292`
- **SHA1:** `e1e36574b3af1ddaab74f5e69505d8836bf12f52`
- **SHA1:** `ce4a123414f9fffa959d1f329c4749da83c4bf10`
- **SHA1:** `c17ac4b5c1cb901a7ccddf00ac9722b8e2725345`
- **SHA1:** `3f401fe1d58fe77e10d665ab713057375e39b887`
- **SHA1:** `f5434e31b6259b4e08684618a305bae127b6d784`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.002** — Compromise Software Supply Chain
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1567** — Exfiltration Over Web Service
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1212** — Exploitation for Credential Access
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1505.003** — Server Software Component: Web Shell
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] CI/CD runner outbound to gist.githubusercontent.com (tj-actions CVE-2025-30066 staging fetch)

`UC_798_4` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime values(All_Traffic.dest_url) as dest_urls values(All_Traffic.process_name) as process_names from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="gist.githubusercontent.com" OR All_Traffic.dest_url="*gist.githubusercontent.com*") by All_Traffic.src, All_Traffic.user, All_Traffic.process_name, All_Traffic.dest, All_Traffic.dest_port | `drop_dm_object_name(All_Traffic)` | where match(process_name, "(?i)(Runner\.Worker|Runner\.Listener|node|curl|wget|python|bash|sh|git)") OR match(src, "(?i)(runner|github-actions|ci-)") | eval firstTime=strftime(firstTime,"%Y-%m-%dT%H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%dT%H:%M:%S") | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "gist.githubusercontent.com" or RemoteUrl endswith "gist.githubusercontent.com"
| where InitiatingProcessFileName in~ ("Runner.Worker.exe","Runner.Worker","Runner.Listener.exe","Runner.Listener","node.exe","node","curl.exe","curl","wget.exe","wget","python.exe","python","python3","bash","sh","git.exe","git")
   or InitiatingProcessParentFileName in~ ("Runner.Worker.exe","Runner.Worker","Runner.Listener.exe","Runner.Listener","node.exe","node")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, InitiatingProcessFolderPath, ReportId
| order by Timestamp desc
```

### [LLM] Runner.Worker process memory dump via memdump.py on CI/CD runner (tj-actions credential theft)

`UC_798_5` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Processes.process) as commandlines, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("python","python.exe","python3","python3.exe") AND (Processes.process="*memdump.py*" OR Processes.process="*Runner.Worker*" OR Processes.process="*/proc/*/mem*" OR Processes.process="*gist.githubusercontent.com*")) OR Processes.process="*memdump.py*" by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | where match(parent_process_name, "(?i)(Runner\.Worker|Runner\.Listener|node|bash|sh)") OR match(dest, "(?i)(runner|github-actions|ci-)") | eval firstTime=strftime(firstTime,"%Y-%m-%dT%H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%dT%H:%M:%S") | sort - lastTime
```

**Defender KQL:**
```kql
let RunnerProcessNames = dynamic(["Runner.Worker.exe","Runner.Worker","Runner.Listener.exe","Runner.Listener","node.exe","node"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("python.exe","python","python3.exe","python3")
         and (ProcessCommandLine has "memdump.py"
              or ProcessCommandLine has "Runner.Worker"
              or ProcessCommandLine matches regex @"(?i)/proc/\d+/mem"
              or ProcessCommandLine has "gist.githubusercontent.com"))
   or ProcessCommandLine has "memdump.py"
| where InitiatingProcessFileName in~ (RunnerProcessNames)
   or InitiatingProcessParentFileName in~ (RunnerProcessNames)
   or DeviceName has_any ("runner","gh-actions","github-actions","ci-","build")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessParentFileName,
          InitiatingProcessCommandLine, FolderPath, SHA256, ReportId
| order by Timestamp desc
```

### [LLM] Compromised tj-actions/changed-files commit SHA referenced on host (CVE-2025-30066 IOC hunt)

`UC_798_6` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, values(Processes.process) as commandlines, min(_time) as firstTime, max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process IN ("*0e58ed8671d6b60d0890c21b07f8835ace038e67*","*6e6023c01918b353229af0881232f601a4cc8365*","*fbc2c5ebe64389f297a7808025379f77133f1292*","*e1e36574b3af1ddaab74f5e69505d8836bf12f52*","*ce4a123414f9fffa959d1f329c4749da83c4bf10*","*c17ac4b5c1cb901a7ccddf00ac9722b8e2725345*","*3f401fe1d58fe77e10d665ab713057375e39b887*","*f5434e31b6259b4e08684618a305bae127b6d784*") by Processes.dest, Processes.user, Processes.process_name, Processes.parent_process_name, Processes.process | `drop_dm_object_name(Processes)` | eval firstTime=strftime(firstTime,"%Y-%m-%dT%H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%dT%H:%M:%S") | sort - lastTime
```

**Defender KQL:**
```kql
let MaliciousSHAs = dynamic(["0e58ed8671d6b60d0890c21b07f8835ace038e67","6e6023c01918b353229af0881232f601a4cc8365","fbc2c5ebe64389f297a7808025379f77133f1292","e1e36574b3af1ddaab74f5e69505d8836bf12f52","ce4a123414f9fffa959d1f329c4749da83c4bf10","c17ac4b5c1cb901a7ccddf00ac9722b8e2725345","3f401fe1d58fe77e10d665ab713057375e39b887","f5434e31b6259b4e08684618a305bae127b6d784"]);
union isfuzzy=true
(
    DeviceProcessEvents
    | where Timestamp > ago(90d)
    | where ProcessCommandLine has_any (MaliciousSHAs) or InitiatingProcessCommandLine has_any (MaliciousSHAs)
    | project Timestamp, EventType="Process", DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, ReportId
),
(
    DeviceFileEvents
    | where Timestamp > ago(90d)
    | where FolderPath has_any (".github/workflows","action.yml","action.yaml",".gitlab-ci.yml")
         or FileName endswith ".yml" or FileName endswith ".yaml"
    | where InitiatingProcessCommandLine has_any (MaliciousSHAs)
    | project Timestamp, EventType="File", DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, ReportId
)
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

### Article-specific behavioural hunt — When 'Changed Files' Changed Everything: Our Black Hat 2025 Presentation on the

`UC_798_3` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — When 'Changed Files' Changed Everything: Our Black Hat 2025 Presentation on the ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("memdump.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("memdump.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — When 'Changed Files' Changed Everything: Our Black Hat 2025 Presentation on the
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("memdump.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("memdump.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-30066`, `CVE-2025-30154`

- **File hash IOCs — endpoint file/process match** ([template](../_TEMPLATES.md#hash-ioc)) — phase: **install**, confidence: **High**
  - file hash IOC(s): `0e58ed8671d6b60d0890c21b07f8835ace038e67`, `6e6023c01918b353229af0881232f601a4cc8365`, `fbc2c5ebe64389f297a7808025379f77133f1292`, `e1e36574b3af1ddaab74f5e69505d8836bf12f52`, `ce4a123414f9fffa959d1f329c4749da83c4bf10`, `c17ac4b5c1cb901a7ccddf00ac9722b8e2725345`, `3f401fe1d58fe77e10d665ab713057375e39b887`, `f5434e31b6259b4e08684618a305bae127b6d784`


## Why this matters

Severity classified as **CRIT** based on: CVE present, IOCs present, 7 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
