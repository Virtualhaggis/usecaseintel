# [HIGH] The GitHub Warning Everyone Ignores: 'This Commit Does Not Belong to Any Branch'

**Source:** StepSecurity
**Published:** 2025-08-09
**Article:** https://www.stepsecurity.io/blog/the-github-warning-everyone-ignores-this-commit-does-not-belong-to-any-branch

## Threat Profile

Back to Blog Resources The GitHub Warning Everyone Ignores: 'This Commit Does Not Belong to Any Branch' Several popular GitHub Actions have release processes where the release commit does not belong to any branch on the action repository. Varun Sharma View LinkedIn June 19, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
In the world of CI/CD automation, GitHub Actions have become indispensable. But there's a troubling securit…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-30066`
- **CVE:** `CVE-2025-30154`
- **SHA1:** `0e58ed8671d6b60d0890c21b07f8835ace038e67`
- **SHA1:** `fbc2c5ebe64389f297a7808025379f77133f1292`
- **SHA1:** `e1e36574b3af1ddaab74f5e69505d8836bf12f52`
- **SHA1:** `ce4a123414f9fffa959d1f329c4749da83c4bf10`
- **SHA1:** `c17ac4b5c1cb901a7ccddf00ac9722b8e2725345`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1027** — Obfuscated Files or Information
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1554** — Compromise Host Software Binary
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1105** — Ingress Tool Transfer
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] GitHub Actions workflow run referencing compromised tj-actions/reviewdog commit SHAs

`UC_684_3` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime values(All_Changes.object) as repo values(All_Changes.user) as actor values(All_Changes.command) as workflow_ref from datamodel=Change.All_Changes where All_Changes.action="workflow_run" (All_Changes.command="*tj-actions/changed-files*" OR All_Changes.command="*reviewdog/action-setup*" OR All_Changes.command="*0e58ed8671d6b60d0890c21b07f8835ace038e67*" OR All_Changes.command="*fbc2c5ebe64389f297a7808025379f77133f1292*" OR All_Changes.command="*e1e36574b3af1ddaab74f5e69505d8836bf12f52*" OR All_Changes.command="*ce4a123414f9fffa959d1f329c4749da83c4bf10*" OR All_Changes.command="*c17ac4b5c1cb901a7ccddf00ac9722b8e2725345*") by host All_Changes.user All_Changes.object All_Changes.command | `drop_dm_object_name(All_Changes)`
```

**Defender KQL:**
```kql
let _badShas = dynamic(["0e58ed8671d6b60d0890c21b07f8835ace038e67","fbc2c5ebe64389f297a7808025379f77133f1292","e1e36574b3af1ddaab74f5e69505d8836bf12f52","ce4a123414f9fffa959d1f329c4749da83c4bf10","c17ac4b5c1cb901a7ccddf00ac9722b8e2725345"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "GitHub"
| where ActionType in~ ("WorkflowRun","WorkflowJob","workflows.completed_workflow_run","workflow_dispatch")
| extend Raw = tostring(RawEventData)
| where Raw has_any (_badShas) or Raw has "tj-actions/changed-files" or Raw has "reviewdog/action-setup"
| extend RepoName = tostring(parse_json(RawEventData).repo), Workflow = tostring(parse_json(RawEventData).workflow), HeadSha = tostring(parse_json(RawEventData).head_sha), Actor = tostring(parse_json(RawEventData).actor)
| project Timestamp, AccountDisplayName, IPAddress, RepoName, Workflow, HeadSha, ActionType, Actor
| order by Timestamp desc
```

### [LLM] CI runner process scrapes another process's memory via /proc/<pid>/maps or /proc/<pid>/mem

`UC_684_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmd values(Processes.parent_process_name) as parent values(Processes.user) as user from datamodel=Endpoint.Processes where Processes.os="Linux" Processes.process_name IN ("python","python3","perl","ruby","bash","sh") (Processes.process="*/proc/*/maps*" OR Processes.process="*/proc/*/mem*" OR Processes.process="*Runner.Worker*") by host Processes.process_name Processes.parent_process_name Processes.user | `drop_dm_object_name(Processes)` | where match(cmd, "/proc/\d+/(maps|mem)")
```

**Defender KQL:**
```kql
let _runnerParents = dynamic(["Runner.Listener","Runner.Worker","runsvc.sh","actions-runner","run.sh","bash","node"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceName !endswith "$"
| where ProcessCommandLine matches regex @"/proc/\d+/(maps|mem)\b"
   or ProcessCommandLine has "Runner.Worker" and ProcessCommandLine has_any ("open(", "readlines", "read(")
| where FileName in~ ("python","python3","perl","ruby","bash","sh","cat","dd","grep")
| extend RunnerContext = iff(InitiatingProcessFolderPath has_any ("/_work/","/actions-runner/","/home/runner/") or InitiatingProcessParentFileName in~ (_runnerParents), "GitHubActionsRunner", "Other")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName, RunnerContext
| order by Timestamp desc
```

### [LLM] GitHub Actions Linux runner pulls payload from gist.githubusercontent.com / raw.githubusercontent.com

`UC_684_5` · phase: **c2** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
`summariesonly` | tstats count min(_time) as firstTime max(_time) as lastTime values(All_Traffic.dest) as dest values(All_Traffic.url) as url values(All_Traffic.process) as proc values(All_Traffic.user) as user from datamodel=Network_Traffic.All_Traffic where (All_Traffic.url="*gist.githubusercontent.com*" OR All_Traffic.url="*raw.githubusercontent.com*") All_Traffic.process_name IN ("curl","wget","python","python3","node","bash","sh") by host All_Traffic.src All_Traffic.process_name | `drop_dm_object_name(All_Traffic)` | search host="*runner*" OR host="*ci*" OR host="*build*"
```

**Defender KQL:**
```kql
let _runnerParents = dynamic(["Runner.Listener","Runner.Worker","runsvc.sh","actions-runner","run.sh"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("gist.githubusercontent.com","raw.githubusercontent.com")
| where InitiatingProcessFileName in~ ("curl","wget","python","python3","node","bash","sh","dash")
| where InitiatingProcessFolderPath has_any ("/_work/","/actions-runner/","/home/runner/","/var/lib/github-runner/") or InitiatingProcessParentFileName in~ (_runnerParents)
| join kind=leftouter (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("python","python3","bash","sh")
    | where ProcessCommandLine has_any ("base64","-c ","eval","exec(")
    | project DeviceId, PayloadPid = ProcessId, PayloadCmd = ProcessCommandLine, PayloadTime = Timestamp
  ) on DeviceId
| where isnull(PayloadTime) or abs(datetime_diff('second', Timestamp, PayloadTime)) <= 120
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, PayloadCmd
| order by Timestamp desc
```

### Article-specific behavioural hunt — The GitHub Warning Everyone Ignores: 'This Commit Does Not Belong to Any Branch'

`UC_684_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The GitHub Warning Everyone Ignores: 'This Commit Does Not Belong to Any Branch' ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — The GitHub Warning Everyone Ignores: 'This Commit Does Not Belong to Any Branch'
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
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
  - file hash IOC(s): `0e58ed8671d6b60d0890c21b07f8835ace038e67`, `fbc2c5ebe64389f297a7808025379f77133f1292`, `e1e36574b3af1ddaab74f5e69505d8836bf12f52`, `ce4a123414f9fffa959d1f329c4749da83c4bf10`, `c17ac4b5c1cb901a7ccddf00ac9722b8e2725345`


## Why this matters

Severity classified as **HIGH** based on: CVE present, IOCs present, 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
