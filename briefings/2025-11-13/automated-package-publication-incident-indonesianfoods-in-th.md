# [HIGH] Automated Package-Publication Incident IndonesianFoods in the NPM Ecosystem Linked to Crypto Reward-Farming Scam

**Source:** Snyk
**Published:** 2025-11-13
**Article:** https://snyk.io/blog/automated-package-publication-incident-indonesianfoods/

## Threat Profile

Snyk Blog In this article
Written by Stephen Thoemmes 
November 13, 2025
0 mins read “Amazon's findings are effectively a continuation of the IndonesianFoods worm activity our team analyzed — a reminder that AI-style automation makes it trivial to publish hundreds of thousands of junk or risky packages at scale. Developers should rely on automated dependency-health guards and behavior-based scanning, not manual review: flagging low-download packages, template-reused content, and sudden mass-publ…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1496** — Resource Hijacking
- **T1071.001** — Application Layer Protocol: Web Protocols

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### IndonesianFoods npm spam package install on developer/CI endpoint

`UC_790_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe") OR Processes.parent_process_name IN ("npm.exe","yarn.exe","pnpm.exe","npx.exe")) AND (Processes.process="*install*" OR Processes.process="* add *" OR Processes.process="* i *") AND (Processes.process="*vointea*" OR Processes.process="*voinzaril*" OR Processes.process="*-wekto*" OR Processes.process="*-riris*" OR Processes.process="*-z3n*" OR Processes.process="*-kyuki*" OR Processes.process="*-breki*" OR Processes.process="*-notthedevs*" OR Processes.process="*ksni-technical-test*") by host Processes.user Processes.dest Processes.process Processes.parent_process_name Processes.process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe")
    or InitiatingProcessFileName in~ ("npm.exe","node.exe","yarn.exe","pnpm.exe","npx.exe")
| extend FullCmd = strcat(tostring(ProcessCommandLine), " || ", tostring(InitiatingProcessCommandLine))
| where FullCmd has_any ("install"," add "," i ")
| where FullCmd matches regex @"(?i)(vointea|voinzaril|-(wekto|riris|z3n|kyuki|breki|notthedevs)|ksni-technical-test)"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### IndonesianFoods auto-publish artifact (auto.js / publishScript.js) dropped in node_modules

`UC_790_3` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where Filesystem.file_path="*\\node_modules\\*" AND (Filesystem.file_name="auto.js" OR Filesystem.file_name="publishScript.js" OR Filesystem.file_name="publish.js") AND Filesystem.action IN ("created","modified") AND (Filesystem.file_path="*vointea*" OR Filesystem.file_path="*voinzaril*" OR Filesystem.file_path="*-wekto*" OR Filesystem.file_path="*-riris*" OR Filesystem.file_path="*-z3n*" OR Filesystem.file_path="*-kyuki*" OR Filesystem.file_path="*-breki*" OR Filesystem.file_path="*-notthedevs*") by host Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("FileCreated","FileModified","FileRenamed")
| where FolderPath has @"\node_modules\"
| where FileName in~ ("auto.js","publishScript.js","publish.js")
| where FolderPath matches regex @"(?i)\\node_modules\\[^\\]*(vointea|voinzaril|-(wekto|riris|z3n|kyuki|breki|notthedevs))[^\\]*\\"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### TEA Protocol (tea.xyz) DNS resolution from developer or build endpoint

`UC_790_4` · phase: **c2** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Resolution.DNS where DNS.query="tea.xyz" OR DNS.query="*.tea.xyz" by host DNS.src DNS.query DNS.dest DNS.answer | `drop_dm_object_name(DNS)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "tea.xyz" or RemoteUrl endswith ".tea.xyz"
| where InitiatingProcessFileName in~ ("node.exe","npm.exe","npx.exe","yarn.exe","pnpm.exe","chrome.exe","msedge.exe","firefox.exe","curl.exe","wget.exe","git.exe")
| summarize FirstSeen = min(Timestamp), LastSeen = max(Timestamp), Hits = count(), arg_max(Timestamp, *) by DeviceName, InitiatingProcessFileName, RemoteUrl
| order by FirstSeen desc
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

### Article-specific behavioural hunt — Automated Package-Publication Incident IndonesianFoods in the NPM Ecosystem Link

`UC_790_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Automated Package-Publication Incident IndonesianFoods in the NPM Ecosystem Link ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("next.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("next.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Automated Package-Publication Incident IndonesianFoods in the NPM Ecosystem Link
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("next.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
