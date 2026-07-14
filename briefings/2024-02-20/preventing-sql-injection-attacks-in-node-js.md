# [HIGH] Preventing SQL injection attacks in Node.js

**Source:** Snyk
**Published:** 2024-02-20
**Article:** https://snyk.io/blog/preventing-sql-injection-attacks-node-js/

## Threat Profile

Snyk Blog In this article
Written by Lucien Chemaly 
February 20, 2024
0 mins read As reliance on software systems continues to grow, so does the emergence of numerous security threats. One notable threat for developers, especially those working with Node.js , is SQL injection.
SQL injection is a malicious attack where nefarious SQL code is injected into a system, exposing sensitive information, corrupting or deleting data, and sometimes, granting unauthorized access to attackers. Addressing thi…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Boolean-tautology SQL injection against Node.js/Express search endpoint

`UC_1375_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.http_method="POST" OR Web.http_method="GET") by Web.src, Web.dest, Web.http_method, Web.url, Web.uri_query, Web.http_user_agent, Web.status
| `drop_dm_object_name(Web)`
| eval probe=lower(url.""+uri_query+url)
| eval inspect=lower(url) . " " . lower(uri_query)
| where match(inspect,"('|%27)\s*(or|and)\s*('|%27)?\s*\d+('|%27)?\s*=\s*('|%27)?\s*\d+") OR match(inspect,"or\s+1\s*=\s*1") OR match(inspect,"('|%27)\s*or\s*('|%27)1('|%27)\s*=\s*('|%27)1") OR match(inspect,"(--|%2d%2d|;%20--|#)\s*$")
| convert ctime(firstTime) ctime(lastTime)
| table firstTime lastTime src dest http_method url uri_query status http_user_agent count
| sort - count
```

### Article-specific behavioural hunt — Preventing SQL injection attacks in Node.js

`UC_1375_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Preventing SQL injection attacks in Node.js ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","app.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js","app.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Preventing SQL injection attacks in Node.js
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "app.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js", "app.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
