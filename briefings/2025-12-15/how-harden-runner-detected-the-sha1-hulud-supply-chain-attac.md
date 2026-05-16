# [HIGH] How Harden Runner Detected the Sha1-Hulud Supply Chain Attack in CNCF's Backstage Repository

**Source:** StepSecurity
**Published:** 2025-12-15
**Article:** https://www.stepsecurity.io/blog/how-harden-runner-detected-the-sha1-hulud-supply-chain-attack-in-cncfs-backstage-repository

## Threat Profile

Back to Blog Threat Intel How Harden Runner Detected the Sha1-Hulud Supply Chain Attack in CNCF's Backstage Repository A case study on detecting npm supply chain attacks through runtime monitoring and baseline anomaly detection Varun Sharma View LinkedIn December 3, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Introduction On November 23-24, 2025, the npm ecosystem experienced one of its largest coordinated supply chain att…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1059.001** — PowerShell
- **T1027** — Obfuscated Files or Information
- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain
- **T1105** — Ingress Tool Transfer
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1133** — External Remote Services
- **T1543** — Create or Modify System Process
- **T1078** — Valid Accounts
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Sha1-Hulud npm Worm — Egress to bun.sh / oss.trufflehog.org / keychecker.trufflesecurity.com from npm/node context

`UC_528_3` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(DNS.query) as query values(DNS.dest) as dest values(DNS.src) as src from datamodel=Network_Resolution.DNS where (DNS.query IN ("bun.sh","oss.trufflehog.org","keychecker.trufflesecurity.com") OR DNS.query="*.bun.sh" OR DNS.query="*.trufflehog.org" OR DNS.query="*.trufflesecurity.com") by host DNS.src DNS.query | `drop_dm_object_name(DNS)` | stats min(firstTime) as firstTime max(lastTime) as lastTime dc(query) as distinct_iocs values(query) as ioc_domains values(dest) as dest_ips by host src | where distinct_iocs >= 1 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
let _iocs = dynamic(["bun.sh","oss.trufflehog.org","keychecker.trufflesecurity.com"]);
let _npm_ctx = dynamic(["node.exe","node","npm.exe","npm-cli.js","yarn.exe","yarn","pnpm.exe","pnpm","bun.exe","bun","bash","sh","runner.listener.exe","runner.worker.exe"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any (_iocs)
     or RemoteUrl endswith ".bun.sh"
     or RemoteUrl endswith ".trufflehog.org"
     or RemoteUrl endswith ".trufflesecurity.com"
| extend NpmContext = InitiatingProcessFileName in~ (_npm_ctx)
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp),
            DistinctIocDomains = dcount(RemoteUrl),
            IocsHit = make_set(RemoteUrl, 10),
            InitiatingProcs = make_set(InitiatingProcessFileName, 10),
            SampleCmd = any(InitiatingProcessCommandLine),
            RemoteIPs = make_set(RemoteIP, 10),
            AnyNpmContext = max(tolong(NpmContext))
          by DeviceId, DeviceName, InitiatingProcessAccountName
| where DistinctIocDomains >= 2 or AnyNpmContext == 1
| order by FirstSeen desc
```

### [LLM] Sha1-Hulud npm Worm — Self-Hosted GitHub Actions Runner Registration with Name 'SHA1HULUD'

`UC_528_4` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.process_path) as process_path values(Processes.parent_process_name) as parent_process_name values(Processes.parent_process) as parent_process from datamodel=Endpoint.Processes where (Processes.process="*SHA1HULUD*" OR (Processes.process_name IN ("config.cmd","config.sh","Runner.Listener.exe","Runner.Listener") AND Processes.process="*--name*" AND (Processes.process="*runner-registration*" OR Processes.process="*--token*"))) by host Processes.user Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "SHA1HULUD"
     or InitiatingProcessCommandLine has "SHA1HULUD"
     or (FileName in~ ("config.cmd","config.sh","Runner.Listener.exe","Runner.Listener")
         and ProcessCommandLine has "--name"
         and ProcessCommandLine has_any ("runner-registration","--token","--unattended"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName,
          FileName, FolderPath, ProcessCommandLine,
          ParentImage = InitiatingProcessFileName,
          ParentCmd   = InitiatingProcessCommandLine,
          GrandParent = InitiatingProcessParentFileName,
          SHA256
| order by Timestamp desc
```

### [LLM] Sha1-Hulud npm Worm — Drop of setup_bun.js / bun_environment.js / discussion.yaml by node or shell

`UC_528_5` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as file_path values(Filesystem.process_name) as process_name values(Filesystem.process_path) as process_path from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("setup_bun.js","bun_environment.js") OR Filesystem.file_path="*\\.github\\workflows\\discussion.yaml" OR Filesystem.file_path="*/.github/workflows/discussion.yaml") AND Filesystem.process_name IN ("node.exe","node","npm.exe","npm-cli.js","yarn.exe","yarn","pnpm.exe","pnpm","bun.exe","bun","bash","sh","cmd.exe","powershell.exe") by host Filesystem.user Filesystem.file_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
let _npm_writers = dynamic(["node.exe","node","npm.exe","npm-cli.js","yarn.exe","yarn","pnpm.exe","pnpm","bun.exe","bun","bash","sh","cmd.exe","powershell.exe","pwsh.exe"]);
DeviceFileEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("setup_bun.js","bun_environment.js")
     or FolderPath has @"\.github\workflows\discussion.yaml"
     or FolderPath has "/.github/workflows/discussion.yaml"
| where InitiatingProcessFileName in~ (_npm_writers)
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### PowerShell encoded / obfuscated command

`UC_PS_OBFUSCATED` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("powershell.exe","pwsh.exe")
      AND (Processes.process="*-enc *" OR Processes.process="*EncodedCommand*"
        OR Processes.process="*FromBase64String*" OR Processes.process="*-nop*"
        OR Processes.process="*-w hidden*" OR Processes.process="*Invoke-Expression*"
        OR Processes.process="*IEX(*" OR Processes.process="*DownloadString*"
        OR Processes.process="*Net.WebClient*")
    by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where AccountName !endswith "$"
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)(-enc|encodedcommand|frombase64string|-nop|-w\s+hidden|invoke-expression|iex\s*\(|downloadstring|net\.webclient)"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — How Harden Runner Detected the Sha1-Hulud Supply Chain Attack in CNCF's Backstag

`UC_528_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — How Harden Runner Detected the Sha1-Hulud Supply Chain Attack in CNCF's Backstag ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("bun.sh"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("bun.sh"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — How Harden Runner Detected the Sha1-Hulud Supply Chain Attack in CNCF's Backstag
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("bun.sh"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("bun.sh"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 6 use case(s) fired, 11 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
