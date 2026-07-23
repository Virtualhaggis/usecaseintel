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

### Auth.js fail-open canary: missing AUTH_SECRET (MissingSecret) config error in app logs

`UC_6_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=app_logs ("[auth][error]" AND ("MissingSecret" OR "AUTH_SECRET"))
| rex field=_raw "(?<AuthError>\[auth\]\[error\][^\n]*)"
| stats count as errorCount, min(_time) as firstSeen, max(_time) as lastSeen, values(AuthError) as sampleError, values(source) as sources by host
| sort - lastSeen
```

### Auth.js fail-open canary: InvalidEndpoints provider misconfiguration in app logs

`UC_6_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=app_logs ("[auth][error]" AND "InvalidEndpoints")
| rex field=_raw "(?<AuthError>\[auth\]\[error\]\s*InvalidEndpoints[^\n]*)"
| stats count as errorCount, min(_time) as firstSeen, max(_time) as lastSeen, values(AuthError) as sampleError, values(source) as sources by host
| sort - lastSeen
```

### Auth.js fail-open bypass: config-error auth log correlated with successful protected-route response

`UC_6_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=app_logs "[auth][error]"
| bin span=5m _time AS errWindow
| stats count as authErrors by errWindow, host
| join type=inner errWindow host [
    search index=web_logs (status=200 OR status=302)
    | search NOT uri_path="/api/auth/*" NOT uri_path="/_next/*"
    | bin span=5m _time AS errWindow
    | stats count as successResponses, values(uri_path) as samplePaths by errWindow, host
  ]
| where authErrors > 0 AND successResponses > 0
| sort - errWindow
```

### Article-specific behavioural hunt — [GHSA / CRITICAL] GHSA-8fpg-xm3f-6cx3: Auth.js: Configuration errors can cause e

`UC_6_0` · phase: **exploit** · confidence: **High**

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
