# [CRIT] [GHSA / CRITICAL] GHSA-g936-7jqj-mwv8: TSDProxy: Internal proxy auth token forwarded to backend services enables management API escalation

**Source:** GitHub Security Advisories
**Published:** 2026-07-10
**Article:** https://github.com/advisories/GHSA-g936-7jqj-mwv8

## Threat Profile

TSDProxy: Internal proxy auth token forwarded to backend services enables management API escalation

## Description

A vulnerability was discovered in TSDProxy where it forwards its internal per-process authentication token to all proxied backend services. When `identityHeaders` is enabled (the default), tsdproxy injects `x-tsdproxy-auth-token` into every upstream HTTP request alongside user identity headers. This token is the same secret used by the management HTTP server to trust forwarded Tai…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1068** — Exploitation for Privilege Escalation
- **T1528** — Steal Application Access Token
- **T1562.001** — Impair Defenses: Disable or Modify Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TSDProxy management API token replay to 127.0.0.1:8080 with spoofed x-tsdproxy-id

`UC_4_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*x-tsdproxy-auth-token*" OR Processes.process="*x-tsdproxy-id*") (Processes.process="*127.0.0.1:8080*" OR Processes.process="*/api/v1/*") by Processes.dest Processes.user Processes.process_name Processes.parent_process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine contains "x-tsdproxy-auth-token" or ProcessCommandLine contains "x-tsdproxy-id"
| where ProcessCommandLine contains "127.0.0.1:8080" or ProcessCommandLine contains "/api/v1/"
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### TSDProxy internal auth token harvest via backend header-reflection endpoint

`UC_4_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*x-tsdproxy-auth-token*" (Processes.process="*/debug/headers*" OR Processes.process="*grep*" OR Processes.process="*python*" OR Processes.process="*curl*") NOT (Processes.process="*/api/v1/*") by Processes.dest Processes.user Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine contains "x-tsdproxy-auth-token" or ProcessCommandLine contains "/debug/headers"
| where not(ProcessCommandLine contains "/api/v1/")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### Exposed/unpatched TSDProxy instance with vulnerable identityHeaders default

`UC_4_2` · phase: **recon** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Processes.process) as cmdlines max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name="tsdproxy" OR Processes.process="*tsdproxy*") by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "tsdproxy" or FolderPath has "tsdproxy" or ProcessCommandLine contains "tsdproxy"
| summarize LastSeen = max(Timestamp), SampleCmds = make_set(ProcessCommandLine, 5) by DeviceName, FileName, FolderPath
| order by LastSeen desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
