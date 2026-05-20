# [MED] actions-cool/issues-helper GitHub Action Compromised: All Tags Point to Imposter Commit That Exfiltrates CI/CD Credentials

**Source:** StepSecurity
**Published:** 2026-05-19
**Article:** https://www.stepsecurity.io/blog/actions-cool-issues-helper-github-action-compromised-all-tags-point-to-imposter-commit-that-exfiltrates-ci-cd-credentials

## Threat Profile

Back to Blog Threat Intel actions-cool/issues-helper GitHub Action Compromised: All Tags Point to Imposter Commit That Exfiltrates CI/CD Credentials The popular GitHub Action actions-cool/issues-helper has been compromised. Every existing tag in the repository has been moved to point to a single imposter commit that does not appear in the action's normal commit history. That commit contains malicious code that exfiltrates credentials from CI/CD pipelines that run the action. Varun Sharma View Li…

## Indicators of Compromise (high-fidelity only)

- **Domain (defanged):** `t.m-kosche.com`

## MITRE ATT&CK Techniques

- **T1071** — Application Layer Protocol
- **T1204.002** — User Execution: Malicious File
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1567** — Exfiltration Over Web Service
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1212** — Exploitation for Credential Access
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1528** — Steal Application Access Token
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1105** — Ingress Tool Transfer
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound C2/exfil to TeamPCP/Shai-Hulud domain t.m-kosche.com

`UC_4_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where (DNS.query="t.m-kosche.com" OR DNS.query="*.m-kosche.com") by DNS.src DNS.query DNS.answer | `drop_dm_object_name(DNS)` | append [| tstats `summariesonly` count from datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest="t.m-kosche.com" OR All_Traffic.dest_host="t.m-kosche.com") by All_Traffic.src All_Traffic.dest All_Traffic.app | `drop_dm_object_name(All_Traffic)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
union
  (DeviceNetworkEvents | where Timestamp > ago(30d) | where RemoteUrl has "m-kosche.com" or RemoteUrl =~ "t.m-kosche.com"),
  (DeviceEvents | where Timestamp > ago(30d) | where ActionType == "DnsQueryResponse" | where AdditionalFields has "m-kosche.com")
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, RemotePort, ReportId
| order by Timestamp desc
```

### [LLM] Linux process reading /proc/<pid>/mem of Runner.Worker (Actions secret theft)

`UC_4_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process) as parent_cmd from datamodel=Endpoint.Processes where Processes.process_name IN ("python3","python","sudo","dd","cat","gdb") (Processes.process="*/proc/*/mem*" OR Processes.process="*Runner.Worker*" OR (Processes.process="*/proc/*" AND Processes.process="*mem*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | where match(cmd, "/proc/\d+/mem") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where DeviceName !endswith "$"
| where FileName in~ ("python3","python","sudo","dd","cat","gdb")
| where ProcessCommandLine matches regex @"/proc/\d+/mem"
   or (ProcessCommandLine has "/proc/" and ProcessCommandLine has "mem" and ProcessCommandLine has_any ("Runner.Worker","isSecret"))
| extend SuspiciousElevation = iif(InitiatingProcessFileName =~ "sudo" or ProcessCommandLine startswith "sudo ", "yes", "no"),
         GitHubRunnerContext = iif(InitiatingProcessCommandLine has_any ("Runner.Worker","Runner.Listener","actions-runner","_work/_actions","actions-cool/issues-helper","bun") or FolderPath has "actions-runner" or InitiatingProcessFolderPath has "actions-runner", "yes", "no")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName, SuspiciousElevation, GitHubRunnerContext, SHA256
| order by Timestamp desc
```

### [LLM] `gh auth token` exfiltration from non-interactive parent on CI/CD host

`UC_4_4` · phase: **actions** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process) as parent_cmd values(Processes.process) as cmd from datamodel=Endpoint.Processes where Processes.process_name="gh" (Processes.process="*auth token*" OR Processes.process="*auth status --show-token*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | search NOT parent_process_name IN ("bash","zsh","fish","sh","pwsh","powershell.exe","cmd.exe","terminal","iTerm2","Windows Terminal") | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "gh" or FileName =~ "gh.exe"
| where ProcessCommandLine has_any ("auth token","auth status --show-token")
| extend RunnerContext = iif(InitiatingProcessFolderPath has "actions-runner" or InitiatingProcessCommandLine has_any ("Runner.Worker","_work/_actions","actions-cool/issues-helper","bun","node /home/runner"), "yes", "no"),
         NonInteractiveParent = iif(InitiatingProcessFileName in~ ("bash","sh","zsh","pwsh","powershell.exe","cmd.exe") and InitiatingProcessParentFileName !in~ ("sshd","sshd-session","terminal","WindowsTerminal.exe","explorer.exe","gnome-terminal-","konsole"), "yes", "no")
| where RunnerContext == "yes" or NonInteractiveParent == "yes"
   or InitiatingProcessFileName in~ ("bun","node","python3","python")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,
          InitiatingProcessParentFileName, RunnerContext, NonInteractiveParent
| order by Timestamp desc
```

### [LLM] Bun runtime download/execution on GitHub Actions self-hosted runner

`UC_4_5` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where (Processes.process_name IN ("bun","bun.exe") OR Processes.process="*bun.sh*" OR Processes.process="*install.sh*bun*" OR Processes.process="*github.com/oven-sh/bun*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | append [| tstats `summariesonly` count from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*/actions-runner/*bun*" OR Filesystem.file_path="*/_work/_actions/actions-cool/issues-helper/*" OR Filesystem.file_name IN ("bun","bun.exe")) by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path | `drop_dm_object_name(Filesystem)`] | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
let runnerProcs = DeviceProcessEvents
  | where Timestamp > ago(30d)
  | where FileName in~ ("bun","bun.exe") or ProcessCommandLine has_any ("bun.sh/install","oven-sh/bun","~/.bun/bin/bun","/home/runner/.bun")
  | extend Source="Process"
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FolderPath, SHA256, Source;
let runnerFiles = DeviceFileEvents
  | where Timestamp > ago(30d)
  | where (FileName in~ ("bun","bun.exe") and (FolderPath has "actions-runner" or FolderPath has "_work" or FolderPath has "/home/runner"))
      or FolderPath has "actions-cool/issues-helper"
  | extend Source="File", AccountName=InitiatingProcessAccountName, ProcessCommandLine=InitiatingProcessCommandLine
  | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, FolderPath, SHA256, Source;
union runnerProcs, runnerFiles
| where InitiatingProcessFolderPath has "actions-runner" or InitiatingProcessCommandLine has_any ("Runner.Worker","_work/_actions","issues-helper") or FolderPath has "actions-runner" or FolderPath has "issues-helper" or FolderPath has "/home/runner"
| order by Timestamp desc
```

### Article-specific behavioural hunt — actions-cool/issues-helper GitHub Action Compromised: All Tags Point to Imposter

`UC_4_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — actions-cool/issues-helper GitHub Action Compromised: All Tags Point to Imposter ```
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
      AND (Filesystem.file_name IN ("index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — actions-cool/issues-helper GitHub Action Compromised: All Tags Point to Imposter
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
| where (FileName in~ ("index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `t.m-kosche.com`


## Why this matters

Severity classified as **MED** based on: IOCs present, 6 use case(s) fired, 12 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
