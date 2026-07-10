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
- **T1190** — Exploit Public-Facing Application
- **T1212** — Exploitation for Credential Access
- **T1552** — Unsecured Credentials

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### netlicensing-mcp get_product called with path-traversal product_number (../token)

`UC_238_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* "netlicensing_get_product" ("../" OR "..\\" OR "%2e%2e" OR "%2f" OR "%5c")
| table _time host source _raw
| sort - _time
```

### NetLicensing REST request URL containing both /product/ and traversal-to-token (wire signature)

`UC_238_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.dest IN ("go.netlicensing.io","netlicensing.labs64.com") AND Web.url="*/product/*" AND (Web.url="*token*" OR Web.url="*%2e%2e*" OR Web.url="*%2f*" OR Web.url="*%5c*" OR Web.url="*/../*") by Web.src Web.dest Web.http_method Web.url
| `drop_dm_object_name(Web)`
| sort - lastTime
```

### netlicensing-mcp get_product response leaking APIKEY/token fields (redaction bypass)

`UC_238_3` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* "netlicensing_get_product" ("ROLE_APIKEY_ADMIN" OR "tokenType" OR "/#/tokens/")
| table _time host source _raw
| sort - _time
```

### First-seen access to NetLicensing /token REST endpoint from MCP egress source

`UC_238_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count earliest(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.dest IN ("go.netlicensing.io","netlicensing.labs64.com") AND Web.url="*/core/v2/rest/token*" by Web.src Web.url
| `drop_dm_object_name(Web)`
| where firstTime > relative_time(now(), "-1d")
| sort - firstTime
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-hxpf-9xvq-wph8: netlicensing-mcp: REST Path Traversal Byp

`UC_238_0` · phase: **exploit** · confidence: **High**

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

Severity classified as **CRIT** based on: 5 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
