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
- **T1041** — Exfiltration Over C2 Channel
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1195.002** — Compromise Software Supply Chain
- **T1003.007** — OS Credential Dumping: Proc Filesystem
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1003** — OS Credential Dumping
- **T1552** — Unsecured Credentials
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Egress to t.m-kosche.com (actions-cool/issues-helper exfil domain)

`UC_2_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="t.m-kosche.com" OR DNS.query="*.m-kosche.com" by DNS.src, DNS.dest, DNS.query | `drop_dm_object_name(DNS)` | appendpipe [ | tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="t.m-kosche.com" OR All_Traffic.url="*t.m-kosche.com*" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app | `drop_dm_object_name(All_Traffic)` ] | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
  (DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has "t.m-kosche.com" or RemoteUrl =~ "t.m-kosche.com"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort, ActionType),
  (DeviceEvents
    | where Timestamp > ago(7d)
    | where ActionType == "DnsQueryResponse"
    | extend QueryName = tostring(parse_json(AdditionalFields).QueryName)
    | where QueryName has "m-kosche.com"
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl=QueryName, RemoteIP="", RemotePort=int(null), ActionType)
| order by Timestamp desc
```

### [LLM] python3 reads /proc/<pid>/mem of Runner.Worker on Linux GitHub Actions runner

`UC_2_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process) as parents from datamodel=Endpoint.Processes where (Processes.process_name="python3" OR Processes.process_name="python" OR Processes.process_name="sudo") AND Processes.process="*/proc/*/mem*" by Processes.dest, Processes.user, Processes.process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("python3", "python", "sudo")
| where ProcessCommandLine matches regex @"(?i)/proc/\d+/mem"
| extend IsRunnerHost = InitiatingProcessFolderPath has_any ("/actions-runner/", "/_work/", "/runner/_work", "/home/runner/")
   or InitiatingProcessParentFileName has_any ("Runner.Worker", "Runner.Listener", "bun")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentFile=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
          ParentParent=InitiatingProcessParentFileName, IsRunnerHost
| order by Timestamp desc
```

### [LLM] tr/grep pipeline extracting 'isSecret':true from Runner memory dump

`UC_2_4` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process="*isSecret*" AND (Processes.process_name="grep" OR Processes.process_name="tr" OR Processes.process_name="awk" OR Processes.process_name="sed" OR Processes.process_name="sh" OR Processes.process_name="bash")) by Processes.dest, Processes.user, Processes.process_name, Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has "isSecret"
| where FileName in~ ("grep", "egrep", "tr", "awk", "sed", "sh", "bash", "dash")
   or InitiatingProcessFileName in~ ("bun", "node", "python3", "sh", "bash")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          ParentFile=InitiatingProcessFileName, ParentCmd=InitiatingProcessCommandLine,
          GrandParent=InitiatingProcessParentFileName
| order by Timestamp desc
```

### [LLM] bun JavaScript runtime executed by GitHub Actions Runner.Worker (anomalous download-and-run)

`UC_2_5` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents values(Processes.process_path) as paths from datamodel=Endpoint.Processes where (Processes.process_name="bun" OR Processes.process_path="*/bun" OR Processes.process="*bun *index.js*") AND (Processes.parent_process_name="Runner.Worker" OR Processes.parent_process="*Runner.Worker*" OR Processes.parent_process_path="*/actions-runner/*" OR Processes.process_path="*/_work/*" OR Processes.process_path="*/home/runner/*") by Processes.dest, Processes.user, Processes.process_name, Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "bun" or FolderPath endswith "/bun" or ProcessCommandLine matches regex @"(?i)\bbun\s+(run\s+)?[\./].*index\.js"
| where InitiatingProcessFileName in~ ("Runner.Worker", "Runner.Listener", "node", "sh", "bash")
   or InitiatingProcessFolderPath has_any ("/actions-runner/", "/_work/", "/home/runner/", "/runner/_work")
   or FolderPath has_any ("/_work/", "/actions-runner/_work/", "/home/runner/")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          ParentFile=InitiatingProcessFileName, ParentPath=InitiatingProcessFolderPath,
          ParentCmd=InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — actions-cool/issues-helper GitHub Action Compromised: All Tags Point to Imposter

`UC_2_1` · phase: **exploit** · confidence: **High**

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
