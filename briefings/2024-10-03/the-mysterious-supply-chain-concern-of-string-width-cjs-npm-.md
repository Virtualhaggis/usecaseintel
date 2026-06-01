# [HIGH] The mysterious supply chain concern of string-width-cjs npm package

**Source:** Snyk
**Published:** 2024-10-03
**Article:** https://snyk.io/blog/supply-chain-string-width-cjs-npm/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
October 3, 2024
0 mins read This story starts when Sébastien Lorber , maintainer of Docusaurus, the React-based open-source documentation project, notices a Pull Request change to the package manifest. Here’s the change proposed to the popular cliui npm package:
Specifically, drawing our attention to the npm dependencies change that use an unfamiliar syntax:
"dependencies" : {
"string-width" : "^5.1.2" ,
"string-width-cjs" : "npm:string-width@^4.2.…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1195.002** — Compromise Software Supply Chain
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] npm/yarn/pnpm install of himanshutester002 suspicious aliased packages (string-width-cjs et al)

`UC_1108_2` · phase: **delivery** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Processes.parent_process_name) as parent values(Processes.process) as cmdline from datamodel=Endpoint.Processes where Processes.process_name IN ("npm.exe","npm-cli.js","yarn.exe","pnpm.exe","npx.exe","node.exe") AND (Processes.process="*string-width-cjs*" OR Processes.process="*strip-ansi-cjs*" OR Processes.process="*wrap-ansi-cjs*" OR Processes.process="*isaacs-cliui*" OR Processes.process="*clazz-transformer*" OR Processes.process="*gh-monoproject-cli*" OR Processes.process="*link-deep*" OR Processes.process="*react-native-multiply*" OR Processes.process="*azure-sdk-for-net*") AND (Processes.process="*install*" OR Processes.process=" i " OR Processes.process=" add " OR Processes.process="*ci*") by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("npm.exe","yarn.exe","pnpm.exe","npx.exe","node.exe") or InitiatingProcessFileName in~ ("npm.exe","yarn.exe","pnpm.exe","npx.exe","node.exe"))
| where ProcessCommandLine has_any ("string-width-cjs","strip-ansi-cjs","wrap-ansi-cjs","isaacs-cliui","clazz-transformer","gh-monoproject-cli","link-deep","react-native-multiply","azure-sdk-for-net")
   or InitiatingProcessCommandLine has_any ("string-width-cjs","strip-ansi-cjs","wrap-ansi-cjs","isaacs-cliui","clazz-transformer","gh-monoproject-cli","link-deep","react-native-multiply","azure-sdk-for-net")
| where ProcessCommandLine has_any ("install"," i "," add "," ci") or InitiatingProcessCommandLine has_any ("install"," i "," add "," ci")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### [LLM] node_modules/ drop of himanshutester002 supply-chain credibility-laundering packages

`UC_1108_3` · phase: **install** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime values(Filesystem.file_path) as paths from datamodel=Endpoint.Filesystem where Filesystem.action=created AND (Filesystem.file_path="*\\node_modules\\string-width-cjs\\*" OR Filesystem.file_path="*\\node_modules\\strip-ansi-cjs\\*" OR Filesystem.file_path="*\\node_modules\\wrap-ansi-cjs\\*" OR Filesystem.file_path="*\\node_modules\\isaacs-cliui\\*" OR Filesystem.file_path="*\\node_modules\\clazz-transformer\\*" OR Filesystem.file_path="*\\node_modules\\gh-monoproject-cli\\*" OR Filesystem.file_path="*\\node_modules\\link-deep\\*" OR Filesystem.file_path="*\\node_modules\\react-native-multiply\\*" OR Filesystem.file_path="*\\node_modules\\azure-sdk-for-net\\*" OR Filesystem.file_path="*/node_modules/string-width-cjs/*" OR Filesystem.file_path="*/node_modules/strip-ansi-cjs/*" OR Filesystem.file_path="*/node_modules/wrap-ansi-cjs/*") by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileRenamed")
| where FolderPath has "node_modules"
| where FolderPath has_any ("\\string-width-cjs\\","\\strip-ansi-cjs\\","\\wrap-ansi-cjs\\","\\isaacs-cliui\\","\\clazz-transformer\\","\\gh-monoproject-cli\\","\\link-deep\\","\\react-native-multiply\\","\\azure-sdk-for-net\\","/string-width-cjs/","/strip-ansi-cjs/","/wrap-ansi-cjs/","/isaacs-cliui/","/clazz-transformer/","/gh-monoproject-cli/","/link-deep/","/react-native-multiply/","/azure-sdk-for-net/")
| where FileName in~ ("package.json","index.js","index.cjs","index.mjs")
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), FileCount=count(), Files=make_set(FileName, 10), Paths=make_set(FolderPath, 5) by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
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

### Article-specific behavioural hunt — The mysterious supply chain concern of string-width-cjs npm package

`UC_1108_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — The mysterious supply chain concern of string-width-cjs npm package ```
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
// Article-specific bespoke detection — The mysterious supply chain concern of string-width-cjs npm package
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

Severity classified as **HIGH** based on: 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
