# [HIGH] Improving GraphQL security with static analysis and Snyk Code

**Source:** Snyk
**Published:** 2022-04-12
**Article:** https://snyk.io/blog/graphql-security-static-analysis-snyk-code/

## Threat Profile

Snyk Blog In this article
Written by Sam Sanoop 
April 12, 2022
0 mins read GraphQL is an API query language developed by Facebook in 2015. Since then, its unique features and capabilities have made it a viable alternative to REST APIs. When it comes to security, GraphQL servers can house several types of misconfigurations that result in data compromise, access control issues, and other high risk vulnerabilities.
While security issues with GraphQL are widely known, there’s little information on …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1571** — Non-Standard Port
- **T1190** — Exploit Public-Facing Application
- **T1554** — Compromise Host Software Binary

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Reverse shell via ncat -e spawned by Node.js app (SonicJS GraphQL path-traversal RCE)

`UC_2290_1` · phase: **c2** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="ncat" OR Processes.process_name="nc" OR Processes.process_name="netcat") Processes.process="*-e*" (Processes.process="*/bin/bash*" OR Processes.process="*/bin/sh*" OR Processes.process="*/bin/dash*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("ncat","nc","netcat")
| where ProcessCommandLine has "-e" and ProcessCommandLine has_any ("/bin/bash","/bin/sh","/bin/dash")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName, SHA256
| order by Timestamp desc
```

### Node.js web process overwriting application .js service file (GraphQL path-traversal file write)

`UC_2290_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action="created" OR Filesystem.action="modified") Filesystem.file_name="*.js" Filesystem.file_path="*/services/*" by Filesystem.dest Filesystem.file_path Filesystem.file_name Filesystem.process_id | `drop_dm_object_name(Filesystem)` | where NOT match(file_path,"node_modules") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node","nodejs")
| where ActionType in ("FileCreated","FileModified")
| where FileName endswith ".js"
| where FolderPath has "/services/"
| where FolderPath !has "/node_modules/"
| where not(InitiatingProcessCommandLine has_any ("npm","yarn","webpack","babel","tsc","rollup","nodemon","install"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, FolderPath, FileName, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Improving GraphQL security with static analysis and Snyk Code

`UC_2290_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Improving GraphQL security with static analysis and Snyk Code ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("service.js","graphql.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/tmp/test.txt*" OR Filesystem.file_name IN ("service.js","graphql.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Improving GraphQL security with static analysis and Snyk Code
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("service.js", "graphql.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/tmp/test.txt") or FileName in~ ("service.js", "graphql.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
