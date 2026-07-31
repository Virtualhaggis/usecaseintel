# [HIGH] Dev Machine Guard Now Scans Extensions Across Every Modern IDE

**Source:** StepSecurity
**Published:** 2026-06-02
**Article:** https://www.stepsecurity.io/blog/dev-machine-guard-now-scans-extensions-across-every-modern-ide

## Threat Profile

Back to Blog Product Dev Machine Guard Now Scans Extensions Across Every Modern IDE Dev Machine Guard now scans IDE extensions across VS Code, Cursor, Windsurf, JetBrains IDEs, Android Studio, Eclipse, and Xcode on macOS, Windows, and Linux. Get a unified inventory, extension risk scoring, typosquat detection, and compromised extension visibility across your entire developer fleet. Swarit Pandey View LinkedIn April 17, 2026
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1195.002** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1546** — Event Triggered Execution
- **T1567.001** — Exfiltration Over Web Service: Exfiltration to Code Repository
- **T1567.002** — Exfiltration Over Web Service: Exfiltration to Cloud Storage
- **T1528** — Steal Application Access Token
- **T1552.004** — Unsecured Credentials: Private Keys
- **T1560.001** — Archive Collected Data: Archive via Utility

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Shai-Hulud npm worm: postinstall bundle.js spawns TruffleHog secret scan

`UC_378_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*trufflehog*" OR Processes.process="*bundle.js*") (Processes.parent_process_name IN ("node","node.exe","npm","npm.cmd","npx","yarn","pnpm","bash","sh","zsh")) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
union
(DeviceProcessEvents
 | where Timestamp > ago(30d)
 | where (FileName has "trufflehog" or ProcessCommandLine has "trufflehog" or ProcessCommandLine has "bundle.js")
 | where InitiatingProcessFileName has_any ("node","npm","npx","yarn","pnpm","sh","bash","zsh")
 | extend Evidence="proc_behaviour"
 | project Timestamp, DeviceName, AccountName, Evidence, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256),
(DeviceFileEvents
 | where Timestamp > ago(30d)
 | where SHA256 in ("b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777","dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c","de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6")
 | extend Evidence="known_bundle_hash", AccountName=InitiatingProcessAccountName
 | project Timestamp, DeviceName, AccountName, Evidence, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine=InitiatingProcessCommandLine, SHA256)
| order by Timestamp desc
```

### Shai-Hulud npm worm: malicious GitHub Actions workflow file dropped (.github/workflows/shai-hulud.yaml)

`UC_378_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name IN ("shai-hulud.yaml","shai-hulud.yml","shai-hulud-workflow.yml","shai-hulud-workflow.yaml")) Filesystem.file_path="*workflows*" by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName in~ ("shai-hulud.yaml","shai-hulud.yml","shai-hulud-workflow.yml","shai-hulud-workflow.yaml")
| where FolderPath has "workflows"
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Shai-Hulud npm worm: secret exfiltration to hardcoded webhook.site endpoint

`UC_378_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*webhook.site*bb8ca5f6-4175-45d2-b042-fc9ebb8170b7*" by Web.src Web.dest Web.url Web.http_method Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "webhook.site"
| where RemoteUrl has "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" or InitiatingProcessFileName in~ ("node","node.exe","npm","npx","curl","curl.exe","wget","git")
| project Timestamp, DeviceName, InitiatingProcessAccountName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### s1ngularity Nx compromise: telemetry.js postinstall harvesting tokens via gh auth token

`UC_378_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*telemetry.js*" OR (Processes.process="*gh*auth*token*" AND Processes.parent_process_name IN ("node","node.exe","npx"))) by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name Processes.parent_process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "telemetry.js" or InitiatingProcessCommandLine has "telemetry.js")
    or (ProcessCommandLine has_all ("gh","auth","token") and InitiatingProcessFileName in~ ("node","node.exe","npx","nx"))
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### s1ngularity Nx compromise: results.b64 credential dump written on developer host

`UC_378_5` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="results.b64" OR Filesystem.file_path="*s1ngularity*") by Filesystem.dest Filesystem.file_name Filesystem.file_path Filesystem.user
| `drop_dm_object_name(Filesystem)`
| convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName =~ "results.b64" or FolderPath has "s1ngularity"
| where InitiatingProcessFileName in~ ("node","node.exe","npm","npx","sh","bash","zsh")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
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

Severity classified as **HIGH** based on: 6 use case(s) fired, 10 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
