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

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### TSDProxy internal auth-token replay to localhost management API

`UC_83_0` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*x-tsdproxy-auth-token*" OR Processes.process="*x-tsdproxy-id*") (Processes.process="*127.0.0.1:8080*" OR Processes.process="*localhost:8080*" OR Processes.process="*/api/v1/*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "x-tsdproxy-auth-token" or ProcessCommandLine has "x-tsdproxy-id"
| where ProcessCommandLine has_any ("127.0.0.1:8080","localhost:8080","/api/v1/")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

### Unauthorized localhost call to TSDProxy /api/v1 management endpoint

`UC_83_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Web.Web where Web.dest_port=8080 (Web.url="*/api/v1/proxies*" OR Web.url="*/api/v1/*") (Web.src="127.0.0.1" OR Web.src="::1") by Web.src Web.dest Web.dest_port Web.http_method Web.url Web.http_user_agent | `drop_dm_object_name(Web)`
```

### Non-TSDProxy backend process connecting to loopback management port 8080

`UC_83_2` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=8080 (All_Traffic.dest="127.0.0.1" OR All_Traffic.dest="::1") All_Traffic.process_name IN ("curl","wget","python","python3","node","php","ruby","perl","sh","bash") by All_Traffic.src_ip All_Traffic.dest All_Traffic.dest_port All_Traffic.process_name | `drop_dm_object_name(All_Traffic)`
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 8080
| where RemoteIP in ("127.0.0.1","::1")
| where InitiatingProcessFileName !in~ ("tsdproxy")
| where InitiatingProcessFileName has_any ("curl","wget","python","python3","node","php","ruby","perl","sh","bash")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
