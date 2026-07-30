# [CRIT] [GHSA / CRITICAL] GHSA-7gfh-x38p-prh3: Velocity.js: Remote Code Execution via property-read to Function constructor (bypass of GHSA-j658-c2gf-x6pq fix)

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-7gfh-x38p-prh3

## Threat Profile

Velocity.js: Remote Code Execution via property-read to Function constructor (bypass of GHSA-j658-c2gf-x6pq fix)

### Summary

Remote Code Execution (RCE) in velocityjs v2.1.6 via property-read to the Function constructor. This bypasses the fix for GHSA-j658-c2gf-x6pq ("Prototype Pollution in #set path assignment") — that advisory blocked constructor/__proto__/prototype only in the #set assignment handler (set.cjs), but property read expressions are unfiltered. Any application rendering attacker…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1190** — Exploit Public-Facing Application
- **T1059.007** — Command and Scripting Interpreter: JavaScript
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Velocity.js SSTI RCE payload (constructor.constructor→child_process) in HTTP request

`UC_94_1` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*constructor.constructor*" OR Web.url="*child_process*" OR Web.url="*mainModule*" OR Web.url="*%23set(*" OR Web.url="*process.mainModule*") by Web.src Web.dest Web.site Web.http_method Web.url Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Node.js process spawning shell / recon binary (velocityjs SSTI RCE execution)

`UC_94_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name IN ("node.exe","node")) AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","hostname.exe","ipconfig.exe","systeminfo.exe","wmic.exe","certutil.exe","bitsadmin.exe","curl.exe","nslookup.exe","sh","bash","dash","whoami","id","uname","curl","wget","nc","ncat")) by Processes.dest Processes.user Processes.parent_process Processes.parent_process_name Processes.process Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node.exe","node")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe","hostname.exe","ipconfig.exe","systeminfo.exe","wmic.exe","certutil.exe","bitsadmin.exe","curl.exe","nslookup.exe","sh","bash","dash","whoami","id","uname","curl","wget","nc","ncat")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256, InitiatingProcessId, ProcessId
| order by Timestamp desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-7gfh-x38p-prh3: Velocity.js: Remote Code Execution via pr

`UC_94_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-7gfh-x38p-prh3: Velocity.js: Remote Code Execution via pr ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("velocity.js","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("velocity.js","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-7gfh-x38p-prh3: Velocity.js: Remote Code Execution via pr
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("velocity.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("velocity.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
