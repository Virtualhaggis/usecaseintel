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

- **T1550.001** — Application Access Token
- **T1068** — Exploitation for Privilege Escalation
- **T1528** — Steal Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TSDProxy management API auth-bypass: forwarded token replayed to 127.0.0.1:8080/api/v1

`UC_5_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*127.0.0.1:8080*" OR Processes.process="*localhost:8080*") AND NOT Processes.process_name="tsdproxy" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| search (process="*x-tsdproxy-auth-token*" OR process="*x-tsdproxy-id*") process="*/api/v1*"
| convert ctime(firstTime) ctime(lastTime)
| table firstTime lastTime dest user process_name parent_process_name process
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("127.0.0.1:8080", "localhost:8080")
| where ProcessCommandLine has "x-tsdproxy-auth-token" or ProcessCommandLine has "x-tsdproxy-id"
| where ProcessCommandLine has "/api/v1"
| where FileName !~ "tsdproxy" and InitiatingProcessFileName !~ "tsdproxy"
| extend HttpMethod = extract(@'(?i)-X\s+([A-Za-z]+)', 1, ProcessCommandLine)
| project Timestamp, DeviceName, AccountName, FileName, HttpMethod, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### TSDProxy internal auth token leakage / capture via backend header reflection

`UC_5_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*x-tsdproxy-auth-token*" AND NOT Processes.process_name="tsdproxy" by Processes.dest Processes.user Processes.process_name Processes.process Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| eval capture_endpoint=if(like(process,"%/debug/headers%"),"yes","no")
| convert ctime(firstTime) ctime(lastTime)
| table firstTime lastTime dest user process_name parent_process_name capture_endpoint process
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "x-tsdproxy-auth-token" or ProcessCommandLine has "/debug/headers"
| where FileName !~ "tsdproxy" and InitiatingProcessFileName !~ "tsdproxy"
| extend TokenHarvest = iff(ProcessCommandLine has "x-tsdproxy-auth-token", "token_string_present", "header_reflection_probe")
| project Timestamp, DeviceName, AccountName, FileName, TokenHarvest, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
