# [CRIT] Sequelize ORM npm library found vulnerable to SQL Injection attacks

**Source:** Snyk
**Published:** 2019-09-11
**Article:** https://snyk.io/blog/sequelize-orm-npm-library-found-vulnerable-to-sql-injection-attacks/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
September 11, 2019
0 mins read Object-Relational Mappers, also commonly referred to as ORMs, are a set of SQL libraries that help developers manage their database code by abstracting it into language constructs.
SQL ORM libraries have been found to be great for SQL Injection prevention , but unfortunately they themselves may have security bugs that open the door for application-level SQL injection attacks .
Why should I care about SQL Injection att…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-10752`
- **CVE:** `CVE-2019-10749`
- **CVE:** `CVE-2019-10748`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Sequelize ORM JSON-path SQLi exploitation via ')) AS DECIMAL)' cast-break (CVE-2019-10748)

`UC_3477_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.uri_query="*AS DECIMAL)*" OR Web.uri_query="*AS%20DECIMAL%29*" OR Web.uri_query="*AS+DECIMAL%29*" OR Web.url="*AS DECIMAL)*" OR Web.url="*AS%20DECIMAL%29*") (Web.uri_query="*UNION*" OR Web.url="*UNION*" OR Web.uri_query="*VERSION(*" OR Web.url="*VERSION(*") by Web.src Web.dest Web.http_method Web.uri_path Web.uri_query Web.status Web.http_user_agent | `drop_dm_object_name(Web)` | where count > 0 | sort - lastTime
```

### Article-specific behavioural hunt — Sequelize ORM npm library found vulnerable to SQL Injection attacks

`UC_3477_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Sequelize ORM npm library found vulnerable to SQL Injection attacks ```
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
// Article-specific bespoke detection — Sequelize ORM npm library found vulnerable to SQL Injection attacks
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2019-10752`, `CVE-2019-10749`, `CVE-2019-10748`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
