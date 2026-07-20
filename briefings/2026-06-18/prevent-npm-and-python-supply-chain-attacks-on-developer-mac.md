# [HIGH] Prevent npm and Python Supply Chain Attacks on Developer Machines with Package Configs

**Source:** StepSecurity
**Published:** 2026-06-18
**Article:** https://www.stepsecurity.io/blog/prevent-npm-and-python-supply-chain-attacks-on-developer-machines-with-package-configs

## Threat Profile

Back to Blog Product Prevent npm and Python Supply Chain Attacks on Developer Machines with Package Configs npm and Python supply chain attacks run on developer machines and steal secrets. See how Package Configs audits registry, cooldown, and auth across your fleet Swarit Pandey View LinkedIn June 16, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav... 
Over the past few months, a wave of supply chain attacks has hit the npm and P…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Supply Chain
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1546** — Event Triggered Execution
- **T1567** — Exfiltration Over Web Service
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1072** — Software Deployment Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Miasma/Hades Bun dropper executed via npm/pip lifecycle hook (setup_bun.js / bun_environment.js)

`UC_281_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*setup_bun.js*" OR Processes.process="*bun_environment.js*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any ("setup_bun.js","bun_environment.js")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### TruffleHog secret-scanning spawned by npm/pip during install (Shai-Hulud credential harvest)

`UC_281_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*trufflehog*" OR Processes.process_name="trufflehog*") AND (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="npm.cmd" OR Processes.parent_process_name="bun.exe" OR Processes.parent_process_name="python.exe" OR Processes.parent_process_name="pip.exe") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName has "trufflehog" or ProcessCommandLine has "trufflehog")
| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","bun.exe","python.exe","pip.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Shai-Hulud/Miasma malicious GitHub Actions workflow file written to .github/workflows

`UC_281_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="shai-hulud-workflow.yml" OR Filesystem.file_name="shai-hulud.yaml" OR Filesystem.file_name="shai-hulud.yml" OR Filesystem.file_name="discussion.yaml") AND Filesystem.file_path="*\\.github\\workflows\\*" by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\.github\workflows\" or FolderPath has "/.github/workflows/"
| where FileName in~ ("shai-hulud-workflow.yml","shai-hulud.yaml","shai-hulud.yml","discussion.yaml")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Developer-runtime exfiltration to webhook.site (Shai-Hulud token drop)

`UC_281_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where Network_Resolution.query="*webhook.site*" by Network_Resolution.src Network_Resolution.query
| `drop_dm_object_name(DNS)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "webhook.site"
| where InitiatingProcessFileName in~ ("node.exe","npm.cmd","bun.exe","python.exe","pip.exe","git.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Mass npm publish from a developer endpoint (worm self-replication)

`UC_281_5` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count as PublishCount min(_time) as firstTime max(_time) as lastTime values(Processes.process) as sampleCmd from datamodel=Endpoint.Processes where (Processes.process="*npm*" AND Processes.process="*publish*") by Processes.dest Processes.user _time span=1h
| `drop_dm_object_name(Processes)`
| where PublishCount >= 5
| convert ctime(firstTime) ctime(lastTime)
| sort - PublishCount
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "npm" and ProcessCommandLine has "publish"
| where AccountName !endswith "$"
| summarize PublishCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp), SampleCmd = any(ProcessCommandLine) by DeviceName, AccountName, bin(Timestamp, 1h)
| where PublishCount >= 5   // worm pushed 286 versions across 57 packages in <2h; human maintainers rarely exceed a few publishes/hour
| order by LastSeen desc
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

Severity classified as **HIGH** based on: 6 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
