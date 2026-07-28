# [CRIT] [GHSA / CRITICAL] GHSA-8fpg-xm3f-6cx3: Auth.js: Configuration errors can cause existence-based auth checks to fail open (auth object populated with an error)

**Source:** GitHub Security Advisories
**Published:** 2026-07-23
**Article:** https://github.com/advisories/GHSA-8fpg-xm3f-6cx3

## Threat Profile

Auth.js: Configuration errors can cause existence-based auth checks to fail open (auth object populated with an error)

### Impact

`next-auth` (Auth.js) v5 applications that gate access by checking only for the **existence** of the `auth` object — the pattern shown in the official [session management / protecting resources guide](https://authjs.dev/getting-started/session-management/protecting) — are affected.

When the Auth.js configuration produces a server-side error, the `auth` object expos…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1204.002** — User Execution: Malicious File
- **T1556** — Modify Authentication Process
- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Auth.js server-configuration error reaching production (fail-open precondition)

`UC_83_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* ("[auth][error]" OR "InvalidEndpoints" OR "MissingSecret" OR "There was a problem with the server configuration")
| stats earliest(_time) as firstSeen latest(_time) as lastSeen count values(source) as sources by host
| convert ctime(firstSeen) ctime(lastSeen)
| sort - lastSeen
```

### Auth.js fail-open exploited: protected routes served 200/302 during an active auth-error window

`UC_83_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
`summariesonly`
| tstats count, values(Web.uri_path) as uri_paths, values(Web.src) as src_ips from datamodel=Web where (Web.status=200 OR Web.status=302) by Web.dest, _time span=10m
| `drop_dm_object_name(Web)`
| join type=inner dest [ search index=* ("[auth][error]" OR "MissingSecret" OR "InvalidEndpoints") | stats count by host | rename host as dest | fields dest ]
| sort - _time
```

### Auth.js config break on deploy: first-ever [auth][error] on a previously-healthy host

`UC_83_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* "[auth][error]" earliest=-1d
| stats min(_time) as firstSeen count values(source) as sources by host
| where firstSeen >= relative_time(now(), "-1d")
| join type=leftanti host [ search index=* "[auth][error]" earliest=-14d latest=-1d | stats count by host | fields host ]
| convert ctime(firstSeen)
| sort - firstSeen
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-8fpg-xm3f-6cx3: Auth.js: Configuration errors can cause e

`UC_83_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-8fpg-xm3f-6cx3: Auth.js: Configuration errors can cause e ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("auth.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("auth.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — [GHSA / CRITICAL] GHSA-8fpg-xm3f-6cx3: Auth.js: Configuration errors can cause e
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("auth.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("auth.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
