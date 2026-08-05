# [HIGH] Type Manipulation: Escaping Template Sandboxes

**Source:** Snyk
**Published:** 2017-03-21
**Article:** https://snyk.io/blog/type-manipulation/

## Threat Profile

Snyk Blog In this article
Written by Guy Podjarny 
March 21, 2017
0 mins read A key property of interpreted languages such as JavaScript and Ruby is dynamic typing, wherein variable types are determined and updated at runtime. Dynamic typing has its downsides, but it can make software more flexible, and development faster. Unfortunately, dynamic typing opens the door to an attack vector called Type Manipulation , in which attackers attempt to modify the type of a given variable and trigger unint…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.004** — Command and Scripting Interpreter: Unix Shell
- **T1003.008** — OS Credential Dumping: /etc/passwd and /etc/shadow
- **T1041** — Exfiltration Over C2 Channel

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Dust.js qs type-manipulation RCE payload in web request query string

`UC_3664_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.uri_query="*child_process*" OR Web.uri_query="*require(*" OR Web.uri_query="*console.log(*" OR Web.uri_query="*%2Fetc%2Fpasswd*" OR Web.uri_query="*/etc/passwd*") by Web.src, Web.dest, Web.http_method, Web.uri_path, Web.uri_query, Web.status, Web.http_user_agent
| `drop_dm_object_name("Web")`
| sort - count
```

### Node.js process spawning shell/curl to read and exfiltrate /etc/passwd (Dust.js post-exploit)

`UC_3664_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node","node.exe","nodejs")) AND (Processes.process_name IN ("sh","bash","dash","zsh","curl","wget")) AND (Processes.process="*/etc/passwd*" OR Processes.process="*/etc/shadow*" OR Processes.process="*child_process*" OR Processes.process="*curl*-F*") by Processes.dest, Processes.user, Processes.parent_process_name, Processes.parent_process, Processes.process_name, Processes.process
| `drop_dm_object_name("Processes")`
| sort - count
```

**Defender KQL:**
```kql
// Node web process shelling out to read/exfil /etc/passwd
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("node","node.exe","nodejs")
| where FileName in~ ("sh","bash","dash","zsh","curl","wget","curl.exe")
| where ProcessCommandLine has_any ("/etc/passwd","/etc/shadow","child_process")
   or ProcessCommandLine matches regex @"(?i)curl\s+.*-F"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Type Manipulation: Escaping Template Sandboxes

`UC_3664_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Type Manipulation: Escaping Template Sandboxes ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("dust.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/etc/passwd*" OR Filesystem.file_name IN ("dust.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Type Manipulation: Escaping Template Sandboxes
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("dust.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/etc/passwd") or FileName in~ ("dust.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **HIGH** based on: 3 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
