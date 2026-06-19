# [CRIT] [GHSA / CRITICAL] GHSA-hxpf-9xvq-wph8: netlicensing-mcp: REST Path Traversal Bypasses Token Redaction

**Source:** GitHub Security Advisories
**Published:** 2026-06-18
**Article:** https://github.com/advisories/GHSA-hxpf-9xvq-wph8

## Threat Profile

netlicensing-mcp: REST Path Traversal Bypasses Token Redaction

## REST Path Traversal Bypasses Token Redaction in netlicensing-mcp

### Summary

The `netlicensing_get_product` MCP tool in `netlicensing-mcp` interpolates a caller-controlled `product_number` argument directly into a REST URL path without any validation. Passing `../token` as the product number causes `httpx` to normalize `/product/../token` into `/token`, silently redirecting the request to the NetLicensing token endpoint instead…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1212** — Exploitation for Credential Access
- **T1190** — Exploit Public-Facing Application
- **T1027** — Obfuscated Files or Information
- **T1087** — Account Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### NetLicensing /token endpoint accessed from MCP server / Python process

`UC_34_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Web.user) as user, values(Web.url) as url, values(Web.src) as src from datamodel=Web.Web where (Web.url="*netlicensing.io*" OR Web.url="*netlicensing.labs64.com*" OR Web.dest="*netlicensing*") AND Web.url="*/core/v2/rest/token*" by Web.src Web.dest Web.http_user_agent Web.app | `drop_dm_object_name(Web)` | where like(http_user_agent,"%python%") OR like(http_user_agent,"%httpx%") OR like(app,"%python%") OR like(app,"%mcp%") | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "/core/v2/rest/token"
   or (RemoteUrl has_any ("netlicensing.io","netlicensing.labs64.com","go.netlicensing.io") and RemoteUrl endswith "/token")
| where InitiatingProcessFileName has_any ("python.exe","python3.exe","pythonw.exe","python","pwsh.exe","node.exe")
   or InitiatingProcessCommandLine has_any ("netlicensing_mcp","netlicensing-mcp","mcp[cli]","netlicensing_get_product")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName,
          RemoteUrl, RemoteIP, RemotePort
| order by Timestamp desc
```

### Path traversal characters in netlicensing_get_product MCP tool invocation

`UC_34_2` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Processes.process) as cmdline, values(Processes.parent_process_name) as parent from datamodel=Endpoint.Processes where Processes.process_name IN ("python.exe","python3.exe","pythonw.exe","python") AND (Processes.process="*netlicensing_get_product*" OR Processes.process="*netlicensing_mcp*" OR Processes.process="*netlicensing-mcp*") AND (Processes.process="*../token*" OR Processes.process="*..\\token*" OR Processes.process="*%2e%2e*" OR Processes.process="*%2ftoken*" OR Processes.process="*%5ctoken*" OR Processes.process="*product_number*../*" OR Processes.process="*product_number*..%2f*") by Processes.host Processes.user Processes.process_name Processes.process Processes.parent_process_name | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("python.exe","python3.exe","pythonw.exe")
   or ProcessCommandLine has_any ("netlicensing_mcp","netlicensing-mcp","netlicensing_get_product")
| where ProcessCommandLine has "netlicensing_get_product"
   or ProcessCommandLine has "product_number"
   or ProcessCommandLine has "/product/"
| where ProcessCommandLine has_any (
        "../token", "..\\token",
        "%2e%2e/", "%2e%2e%2f", "%2e%2e%5c",
        "%2ftoken", "%5ctoken",
        "..%2f", "..%5c",
        "/product/../", "\\product\\..\\")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessParentFileName
| order by Timestamp desc
```

### URL-encoded path traversal targeting NetLicensing /product/ REST API

`UC_34_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count, min(_time) as firstTime, max(_time) as lastTime, values(Web.url) as urls, values(Web.user) as user, values(Web.http_user_agent) as ua from datamodel=Web.Web where (Web.dest="*netlicensing*" OR Web.url="*netlicensing.io*" OR Web.url="*netlicensing.labs64.com*") AND Web.url="*/product/*" AND (Web.url="*%2e%2e*" OR Web.url="*%252e%252e*" OR Web.url="*%2ftoken*" OR Web.url="*%5ctoken*" OR Web.url="*..%2f*" OR Web.url="*..%5c*" OR Web.url="*..%252f*") by Web.src Web.dest | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("netlicensing.io","netlicensing.labs64.com","go.netlicensing.io")
| where RemoteUrl has "/product/"
| where RemoteUrl matches regex @"(?i)/product/[^?#]*(%2e%2e|%252e%252e|%2ftoken|%5ctoken|\.\.%2f|\.\.%5c|\.\.%252f)"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          RemoteUrl, RemoteIP
| order by Timestamp desc
```

### Behavioral: NetLicensing /product/ traversal followed by /token endpoint hit within 5 minutes

`UC_34_4` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true min(_time) as ProductTime, max(_time) as ProductTimeLast, values(Web.url) as ProductUrl from datamodel=Web.Web where Web.dest="*netlicensing*" AND Web.url="*/product/*" AND (Web.url="*..*" OR Web.url="*%2e%2e*" OR Web.url="*%2f*" OR Web.url="*%5c*") by Web.src | `drop_dm_object_name(Web)` | rename src as ProductSrc | join type=inner ProductSrc [| tstats summariesonly=true min(_time) as TokenTime, values(Web.url) as TokenUrl from datamodel=Web.Web where Web.dest="*netlicensing*" AND Web.url="*/core/v2/rest/token*" by Web.src | `drop_dm_object_name(Web)` | rename src as ProductSrc] | where TokenTime >= ProductTime AND TokenTime <= ProductTime + 300 | eval DelaySec = TokenTime - ProductTime | convert ctime(ProductTime) ctime(TokenTime) | table ProductSrc, ProductTime, ProductUrl, TokenTime, TokenUrl, DelaySec
```

**Defender KQL:**
```kql
let WindowSec = 300;
let Traversal = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any ("netlicensing.io","netlicensing.labs64.com","go.netlicensing.io")
    | where RemoteUrl has "/product/"
    | where RemoteUrl matches regex @"(?i)/product/[^?#]*(\.\.|%2e%2e|%2ftoken|%5ctoken|\.\.%2f|\.\.%5c)"
    | project ProductTime = Timestamp, DeviceId, DeviceName, ProductUrl = RemoteUrl,
              InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName;
let TokenHits = DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemoteUrl has_any ("netlicensing.io","netlicensing.labs64.com","go.netlicensing.io")
    | where RemoteUrl has "/core/v2/rest/token"
    | project TokenTime = Timestamp, DeviceId, TokenUrl = RemoteUrl;
Traversal
| join kind=inner TokenHits on DeviceId
| where TokenTime between (ProductTime .. ProductTime + WindowSec * 1s)
| extend DelaySec = datetime_diff('second', TokenTime, ProductTime)
| project ProductTime, TokenTime, DelaySec, DeviceName,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, ProductUrl, TokenUrl
| order by ProductTime desc
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-hxpf-9xvq-wph8: netlicensing-mcp: REST Path Traversal Byp

`UC_34_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-hxpf-9xvq-wph8: netlicensing-mcp: REST Path Traversal Byp ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("redaction.py","server.py","client.py","poc.py"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_name IN ("redaction.py","server.py","client.py","poc.py"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-hxpf-9xvq-wph8: netlicensing-mcp: REST Path Traversal Byp
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("redaction.py", "server.py", "client.py", "poc.py"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env") or FileName in~ ("redaction.py", "server.py", "client.py", "poc.py"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 5 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
