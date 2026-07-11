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

- **T1528** — Steal Application Access Token
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TSDProxy internal auth token (x-tsdproxy-auth-token) captured/handled in host process command line

`UC_2_0` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where Processes.process="*x-tsdproxy-auth-token*" by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "x-tsdproxy-auth-token"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```

### TSDProxy management-API auth bypass: spoofed x-tsdproxy-id replay to 127.0.0.1:8080/api/v1

`UC_2_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process values(Processes.parent_process_name) as parent_process_name from datamodel=Endpoint.Processes where Processes.process="*x-tsdproxy-id*" AND (Processes.process="*127.0.0.1:8080*" OR Processes.process="*localhost:8080*" OR Processes.process="*/api/v1/*") by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "x-tsdproxy-id"
| where ProcessCommandLine has_any ("127.0.0.1:8080","localhost:8080","/api/v1/")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, SHA256
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
