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
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1548.003** — Abuse Elevation Control Mechanism: Sudo and Sudo Caching
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1199** — Trusted Relationship

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Outbound C2 to t.m-kosche.com from CI/CD runner or any endpoint

`UC_40_2` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(DNS.src) as src values(DNS.query) as query from datamodel=Network_Resolution.DNS where DNS.query="*m-kosche.com" by DNS.src DNS.query | `drop_dm_object_name(DNS)` | append [| tstats summariesonly=true count from datamodel=Web.Web where Web.url="*m-kosche.com*" OR Web.dest="*m-kosche.com*" by Web.src Web.dest Web.url | `drop_dm_object_name(Web)`] | append [| tstats summariesonly=true count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest="*m-kosche.com*" by All_Traffic.src All_Traffic.dest | `drop_dm_object_name(All_Traffic)`]
```

**Defender KQL:**
```kql
let exfil_domain = "m-kosche.com";
union isfuzzy=true
(DeviceNetworkEvents
  | where Timestamp > ago(30d)
  | where RemoteUrl has exfil_domain or RemoteUrl endswith ".m-kosche.com"
  | project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName, RemoteUrl, RemoteIP, RemotePort, ActionType),
(DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("DnsQueryResponse","ConnectionSuccess")
  | where RemoteUrl has exfil_domain or AdditionalFields has exfil_domain
  | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, AdditionalFields)
| order by Timestamp desc
```

### [LLM] python3 reading /proc/<PID>/mem to scrape Runner.Worker secrets

`UC_40_3` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("python","python3") AND (Processes.process="*/proc/*/mem*" OR Processes.process="*isSecret*" OR Processes.process="*Runner.Worker*") by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where match(cmdline, "(?i)/proc/\d+/mem") OR match(cmdline, "(?i)isSecret|Runner\.Worker")
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName matches regex @"^python3?(\.\d+)?$" or InitiatingProcessFileName matches regex @"^python3?(\.\d+)?$"
| where ProcessCommandLine matches regex @"/proc/\d+/mem"
   or ProcessCommandLine has_any ("isSecret","Runner.Worker")
   or InitiatingProcessCommandLine matches regex @"/proc/\d+/mem"
| extend ProcMemTarget = extract(@"/proc/(\d+)/mem", 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, ProcMemTarget, SHA256
| order by Timestamp desc
```

### [LLM] bun runtime executed on CI runner spawning python3 with sudo escalation

`UC_40_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as bun_cmd values(Processes.user) as user from datamodel=Endpoint.Processes where (Processes.process_name=bun OR Processes.process="*bun*" OR Processes.process="*/bun *") by Processes.dest Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | join type=inner dest [| tstats summariesonly=true count from datamodel=Endpoint.Processes where Processes.parent_process_name=bun (Processes.process_name IN ("python","python3","sudo") OR Processes.process="*gh auth token*") by Processes.dest Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | rename process as child_cmd process_name as child_name]
```

**Defender KQL:**
```kql
let lookback = 30d;
let BunHosts = DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName =~ "bun" or FolderPath endswith "/bun" or ProcessCommandLine matches regex @"(?i)(curl|wget)[^\n]*bun\.sh"
    | project BunTime = Timestamp, DeviceId, DeviceName, BunPid = ProcessId, BunCmd = ProcessCommandLine, BunParent = InitiatingProcessFileName;
DeviceProcessEvents
| where Timestamp > ago(lookback)
| where InitiatingProcessFileName =~ "bun"
| where FileName in~ ("python","python3","sudo","gh")
   or ProcessCommandLine has_any ("gh auth token","sudo python3","/proc/","isSecret")
| join kind=inner BunHosts on DeviceId
| where Timestamp between (BunTime .. BunTime + 10m)
| project Timestamp, DeviceName, AccountName, BunTime, BunCmd, BunParent, ChildImage = FileName, ChildCmd = ProcessCommandLine, ChildSha256 = SHA256
| order by Timestamp desc
```

### [LLM] GitHub workflow references actions-cool/issues-helper or maintain-one-comment by tag

`UC_40_5` · phase: **delivery** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Changes.user) as user values(All_Changes.object) as workflow from datamodel=Change.All_Changes where All_Changes.object_category="file" AND All_Changes.object_path="*.github/workflows/*" AND (All_Changes.change_type="modification" OR All_Changes.change_type="created") by All_Changes.src All_Changes.object_path | `drop_dm_object_name(All_Changes)` | append [search index=github_audit OR sourcetype=github:* ("actions-cool/issues-helper" OR "actions-cool/maintain-one-comment") | stats count min(_time) as firstTime max(_time) as lastTime by repo workflow actor action_ref] | search (workflow="*actions-cool/issues-helper*" OR workflow="*actions-cool/maintain-one-comment*" OR action_ref="*actions-cool/issues-helper*" OR action_ref="*actions-cool/maintain-one-comment*")
```

### Article-specific behavioural hunt — actions-cool/issues-helper GitHub Action Compromised: All Tags Point to Imposter

`UC_40_1` · phase: **exploit** · confidence: **High**

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

Severity classified as **MED** based on: IOCs present, 6 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
