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
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059** — Command and Scripting Interpreter
- **T1083** — File and Directory Discovery
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service
- **T1567** — Exfiltration Over Web Service
- **T1074.001** — Data Staged: Local Data Staging
- **T1005** — Data from Local System
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1552.006** — Unsecured Credentials: Group Policy Preferences
- **T1059.006** — Command and Scripting Interpreter: Python

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### s1ngularity Nx postinstall — `gh auth token` spawned by node/npm on CI runner

`UC_547_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node","npm","npx","yarn","pnpm") Processes.process_name="gh" Processes.process="*auth*token*" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where like(parent_process,"%postinstall%") OR like(parent_process,"%telemetry.js%") OR like(parent_process,"%nx%") OR firstTime=lastTime | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","npm","npx","yarn","pnpm")
| where FileName =~ "gh"
| where ProcessCommandLine has "auth" and ProcessCommandLine has "token"
| extend SuspectPostInstall = InitiatingProcessCommandLine has_any ("postinstall","telemetry.js","nx/","/@nx/","node_modules")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SuspectPostInstall, InitiatingProcessParentFileName
| order by Timestamp desc
```

### AI CLI weaponized for recon — claude/gemini/q invoked under npm install lineage

`UC_547_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("node","npm","npx","yarn","pnpm","sh","bash") (Processes.process_name IN ("claude","gemini","q") OR Processes.process IN ("*claude --dangerously*","*gemini --yolo*","* q chat*")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process | `drop_dm_object_name(Processes)` | where like(parent_process,"%postinstall%") OR like(parent_process,"%telemetry.js%") OR like(parent_process,"%node_modules%") | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("node","npm","npx","yarn","pnpm","sh","bash")
| where FileName in~ ("claude","gemini","q")
   or ProcessCommandLine has_any ("claude --dangerously-skip-permissions","gemini --yolo","q chat --trust-all-tools")
| extend InstallContext = InitiatingProcessCommandLine has_any ("postinstall","telemetry.js","node_modules","@nx/","npm install","npm ci","yarn install","pnpm install")
| where InstallContext
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| order by Timestamp desc
```

### CI runner anomalous outbound to raw.githubusercontent.com / gist.githubusercontent.com

`UC_547_3` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as urls from datamodel=Web.Web where (Web.url="*raw.githubusercontent.com*" OR Web.url="*gist.githubusercontent.com*" OR Web.dest_host IN ("raw.githubusercontent.com","gist.githubusercontent.com")) by Web.dest Web.dest_host Web.src Web.user Web.url Web.user_agent | `drop_dm_object_name(Web)` | search src IN ("runner-*","gh-runner-*","actions-*") OR user_agent IN ("curl/*","Wget/*","Go-http-client/*","python-requests/*") | eval window=case(firstTime>=relative_time(now(),"-1h"),"new_in_last_hour",1=1,"historical") | where window="new_in_last_hour"
```

**Defender KQL:**
```kql
let LookbackBaseline = 30d;
let Window = 1h;
let RunnerPattern = dynamic(["runner","gh-runner","actions-runner","ghr-"]);
let Baseline = DeviceNetworkEvents
| where Timestamp between (ago(LookbackBaseline) .. ago(Window))
| where RemoteUrl has_any ("raw.githubusercontent.com","gist.githubusercontent.com")
| where DeviceName has_any (RunnerPattern)
| summarize by DeviceName, RemoteUrl;
DeviceNetworkEvents
| where Timestamp > ago(Window)
| where RemoteUrl has_any ("raw.githubusercontent.com","gist.githubusercontent.com")
| where DeviceName has_any (RunnerPattern)
| where InitiatingProcessFileName in~ ("curl","wget","node","python","python3","bash","sh","go")
| join kind=leftanti Baseline on DeviceName, RemoteUrl
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### s1ngularity collection artifact — `/tmp/inventory.txt` written by node/npm on runner

`UC_547_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/tmp/inventory.txt" OR Filesystem.file_name="inventory.txt" OR Filesystem.file_path="*results.b64") Filesystem.process_name IN ("node","npm","npx","yarn","pnpm","sh","bash") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath =~ "/tmp" and FileName =~ "inventory.txt")
   or FileName endswith ".b64" and FileName has "results"
   or FolderPath has "/tmp" and FileName =~ "results.b64"
| where InitiatingProcessFileName in~ ("node","npm","npx","yarn","pnpm","sh","bash")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### GitHub Actions runner — process reads runner worker memory to extract GITHUB_TOKEN

`UC_547_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="/proc/*/mem" OR Filesystem.file_path="/proc/*/maps" OR Filesystem.file_path="/proc/*/environ") Filesystem.process_name IN ("python","python3","node","sh","bash","curl","wget") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.process_name Filesystem.process | `drop_dm_object_name(Filesystem)` | search dest IN ("runner-*","gh-runner-*","actions-runner-*")
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileAccessed")
| where FolderPath startswith "/proc/" and (FileName in ("mem","maps","environ"))
| where InitiatingProcessFileName in~ ("python","python3","node","bash","sh","curl","wget","go")
| where DeviceName has_any ("runner","gh-runner","actions-runner","ghr-")
| extend WorkerHint = InitiatingProcessCommandLine has_any ("Runner.Worker","actions-runner","_diag")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, FileName, WorkerHint
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

Severity classified as **HIGH** based on: 6 use case(s) fired, 13 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
