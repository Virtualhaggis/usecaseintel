# [CRIT] JavaScript type confusion: Bypassed input validation (and how to remediate)

**Source:** Snyk
**Published:** 2021-11-03
**Article:** https://snyk.io/blog/remediate-javascript-type-confusion-bypassed-input-validation/

## Threat Profile

Snyk Blog In this article
Written by Alessio Della Libera 
November 3, 2021
0 mins read In a previous blog post, we showed how type manipulation (or type confusion) can be used to escape template sandboxes, leading to cross-site scripting (XSS) or code injection vulnerabilities.
One of the main goals for this research was to explore (in the JavaScript ecosystem) how and if it is possible to bypass some security fixes or input validations with a type confusion attack (i.e by providing an unexpect…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-23434`
- **CVE:** `CVE-2021-23436`
- **CVE:** `CVE-2021-23438`
- **CVE:** `CVE-2021-23440`
- **CVE:** `CVE-2021-23443`
- **CVE:** `CVE-2021-23444`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Prototype pollution / type-confusion payload in web request (__proto__, constructor[prototype])

`UC_2793_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.uri_query="*__proto__*" OR Web.uri_query="*%5f%5f*proto*" OR Web.uri_query="*constructor[prototype]*" OR Web.uri_query="*constructor%5bprototype%5d*" OR Web.uri_query="*[constructor][prototype]*" OR Web.uri_query="*[__proto__]*" OR Web.uri_path="*__proto__*") by Web.src Web.dest Web.site Web.http_method Web.uri_path Web.uri_query Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Article-specific behavioural hunt — JavaScript type confusion: Bypassed input validation (and how to remediate)

`UC_2793_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — JavaScript type confusion: Bypassed input validation (and how to remediate) ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("edge.js","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("edge.js","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — JavaScript type confusion: Bypassed input validation (and how to remediate)
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("edge.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("edge.js", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-23434`, `CVE-2021-23436`, `CVE-2021-23438`, `CVE-2021-23440`, `CVE-2021-23443`, `CVE-2021-23444`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
