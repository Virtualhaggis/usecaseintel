# [CRIT] Modernizing SAST rules maintenance to catch vulnerabilities faster

**Source:** Snyk
**Published:** 2022-04-19
**Article:** https://snyk.io/blog/modernizing-sast-rules-maintenance-catch-vulnerabilities-faster/

## Threat Profile

Snyk Blog In this article
Written by Frank Fischer 
April 19, 2022
0 mins read Snyk Code separates itself from the majority of static code analysis tools by generating and maintaining rule sets for its users — helping them combat common and newly discovered threats. A recent Hub article described a new Javascript vulnerability called prototype pollution , which allows attackers to modify, or “pollute”, a Javascript object prototype and execute a variety of malicious actions.
In this post, we’ll …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-23682`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Prototype pollution attempt via __proto__ in URL query string (CVE-2021-23682, litespeed.js/appwrite)

`UC_2154_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.uri_query="*__proto__*" OR Web.uri_query="*constructor[prototype]*" OR Web.uri_query="*constructor%5Bprototype%5D*" OR Web.url="*__proto__[*" OR Web.url="*__proto__%5B*") by Web.src, Web.dest, Web.site, Web.http_user_agent, Web.uri_path, Web.uri_query, Web.status, Web.http_method
| `drop_dm_object_name(Web)`
| eval is_signup=if(like(uri_path,"%/auth/signup%"),1,0)
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Article-specific behavioural hunt — Modernizing SAST rules maintenance to catch vulnerabilities faster

`UC_2154_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Modernizing SAST rules maintenance to catch vulnerabilities faster ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("litespeed.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("litespeed.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Modernizing SAST rules maintenance to catch vulnerabilities faster
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("litespeed.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("litespeed.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-23682`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
