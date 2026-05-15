# [HIGH] When 'Changed Files' Changed Everything: Our Black Hat 2025 Presentation on the tj-actions Supply Chain Breach

**Source:** StepSecurity
**Published:** 2025-08-15
**Article:** https://www.stepsecurity.io/blog/when-changed-files-changed-everything-our-black-hat-2025-presentation-on-the-tj-actions-supply-chain-breach

## Threat Profile

Back to Blog Threat Intel When 'Changed Files' Changed Everything: Our Black Hat 2025 Presentation on the tj-actions Supply Chain Breach We reveal how baseline-driven monitoring caught one of 2025's most consequential CI/CD supply chain attacks, exposing the vulnerability of 23,000+ repositories including those from GitHub, Meta, and Microsoft. Ashish Kurmi View LinkedIn August 12, 2025
Share on X Share on X Share on LinkedIn Share on Facebook Follow our RSS feed 
Table of Contents Loading nav..…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.006** — Command and Scripting Interpreter: Python
- **T1003** — OS Credential Dumping
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1105** — Ingress Tool Transfer
- **T1071.001** — Application Layer Protocol: Web Protocols
- **T1102** — Web Service

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] tj-actions/changed-files supply chain: memdump.py fetched from attacker gist on CI runner (CVE-2025-30066)

`UC_669_2` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process values(Processes.user) as user values(Processes.process_name) as process_name from datamodel=Endpoint.Processes where (Processes.process="*gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965*" OR Processes.process="*nikitastupin/30e525b776c409e03c2d6f328f254965*" OR Processes.process="*/raw/memdump.py*" OR Processes.process="*memdump.py*") by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// CVE-2025-30066 — tj-actions/changed-files memdump.py credential dump
DeviceProcessEvents
| where Timestamp > ago(60d)
| where ProcessCommandLine has_any (
    "gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965",
    "nikitastupin/30e525b776c409e03c2d6f328f254965",
    "30e525b776c409e03c2d6f328f254965")
   or ProcessCommandLine has "memdump.py"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
          ProcessCommandLine, SHA256,
          ParentImage = InitiatingProcessFileName,
          ParentCmd   = InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

### [LLM] CI/CD runner outbound to attacker gist (gist.githubusercontent.com/nikitastupin/30e525b776...)

`UC_669_3` · phase: **c2** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.url) as url values(Web.user) as user values(Web.dest) as dest values(Web.http_user_agent) as ua values(Web.http_method) as method from datamodel=Web.Web where (Web.url="*gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965*" OR Web.url="*nikitastupin/30e525b776c409e03c2d6f328f254965/raw*" OR Web.url="*memdump.py*") by Web.src Web.user Web.dest
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
// CVE-2025-30066 — outbound to attacker-controlled gist hosting memdump.py
DeviceNetworkEvents
| where Timestamp > ago(60d)
| where RemoteUrl has "gist.githubusercontent.com"
   or InitiatingProcessCommandLine has "gist.githubusercontent.com"
| where RemoteUrl has_any ("nikitastupin","30e525b776c409e03c2d6f328f254965","memdump.py")
     or InitiatingProcessCommandLine has_any ("nikitastupin/30e525b776c409e03c2d6f328f254965","memdump.py","30e525b776c409e03c2d6f328f254965")
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, RemotePort,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFolderPath, InitiatingProcessAccountName,
          InitiatingProcessParentFileName
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

`UC_669_1` · phase: **exploit** · confidence: **High**

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


## Why this matters

Severity classified as **HIGH** based on: 4 use case(s) fired, 8 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
