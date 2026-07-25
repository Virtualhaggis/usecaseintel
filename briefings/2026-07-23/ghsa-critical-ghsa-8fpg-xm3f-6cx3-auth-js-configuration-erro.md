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
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Auth.js v5 fail-open trigger: server-configuration error emitted in app logs

`UC_54_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* ("[auth][error]") ("InvalidEndpoints" OR "MissingSecret" OR "AUTH_SECRET" OR "problem with the server configuration")
| stats count min(_time) as firstTime max(_time) as lastTime values(_raw) as sampleLog by host, source, sourcetype
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

### Auth.js fail-open: protected-route access succeeds during a config-error window

`UC_54_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.status IN ("200","302") Web.url="/api/*" NOT Web.url="/api/auth*" by _time span=5m, Web.site, Web.src, Web.url, Web.status
| rename Web.* as *
| join type=inner _time [
    search index=* "[auth][error]"
    | bin _time span=5m
    | stats count as authErrors by _time ]
| where authErrors > 0
| stats sum(count) as okProtectedReqs values(url) as urls values(src) as sourceIPs by _time, site
| sort - _time
```

### Auth.js: protected /api access returning success with no session cookie (fail-open evidence)

`UC_54_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* sourcetype=*:access* (status=200 OR status=302) uri_path="/api/*" NOT uri_path="/api/auth*" NOT cookie="*authjs.session-token*"
| stats count as reqs values(uri_path) as paths dc(src_ip) as srcIPs by host, src_ip
| where reqs > 0
| sort - reqs
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-8fpg-xm3f-6cx3: Auth.js: Configuration errors can cause e

`UC_54_0` · phase: **exploit** · confidence: **High**

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
