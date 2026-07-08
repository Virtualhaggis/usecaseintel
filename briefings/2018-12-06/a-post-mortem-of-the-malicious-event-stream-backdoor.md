# [HIGH] A post-mortem of the malicious event-stream backdoor

**Source:** Snyk
**Published:** 2018-12-06
**Article:** https://snyk.io/blog/a-post-mortem-of-the-malicious-event-stream-backdoor/

## Threat Profile

Snyk Blog In this article
Written by Danny Grander 
Liran Tal 
December 6, 2018
0 mins read Last week the imaginable happened. A malicious package, flatmap-stream, was published to npm and was later added as a dependency to the widely used event-stream package by user right9ctrl . Some time, and 8 million downloads later, applications all over the web were unwittingly running malicious code in production. We wrote some early thoughts on our blog last week , moments after the incident came to lig…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1195.001** — Compromise Software Dependencies and Development Tools
- **T1195.002** — Compromise Software Supply Chain
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Malicious flatmap-stream npm package present in node_modules (event-stream supply-chain backdoor)

`UC_3556_1` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_path="*\\node_modules\\flatmap-stream\\*" OR Filesystem.file_path="*/node_modules/flatmap-stream/*") by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.action Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has @"\node_modules\flatmap-stream\" or FolderPath contains "/node_modules/flatmap-stream/"
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Build-time injection into vendored @zxing ReedSolomonDecoder.js (Copay wallet stealer payload)

`UC_3556_2` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.file_name="ReedSolomonDecoder.js" AND (Filesystem.file_path="*\\@zxing\\library\\esm5\\core\\common\\reedsolomon\\*" OR Filesystem.file_path="*/@zxing/library/esm5/core/common/reedsolomon/*") AND Filesystem.action=modified) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.action Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName =~ "ReedSolomonDecoder.js"
| where FolderPath has @"\@zxing\library\esm5\core\common\reedsolomon" or FolderPath contains "/@zxing/library/esm5/core/common/reedsolomon"
| where ActionType in ("FileModified", "FileRenamed")
| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

### Article-specific behavioural hunt — A post-mortem of the malicious event-stream backdoor

`UC_3556_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — A post-mortem of the malicious event-stream backdoor ```
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
// Article-specific bespoke detection — A post-mortem of the malicious event-stream backdoor
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


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
