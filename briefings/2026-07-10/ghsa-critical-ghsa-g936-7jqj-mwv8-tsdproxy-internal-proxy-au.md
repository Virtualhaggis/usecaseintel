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

### TSDProxy management-API token replay via CLI to loopback (x-tsdproxy-auth-token + x-tsdproxy-id)

`UC_116_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process="*x-tsdproxy-auth-token*" AND (Processes.process="*127.0.0.1:8080*" OR Processes.process="*x-tsdproxy-id*" OR Processes.process="*/api/v1/*")) by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has "x-tsdproxy-auth-token"
| where ProcessCommandLine has_any ("127.0.0.1:8080","x-tsdproxy-id","/api/v1/")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

### TSDProxy management API access on loopback (/api/v1) with forged x-tsdproxy-id in proxy logs

`UC_116_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/api/v1/*" AND (Web.dest_port=8080 OR Web.dest="127.0.0.1")) by Web.src Web.dest Web.dest_port Web.http_method Web.url Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime)
```

### TSDProxy forwarded auth-token harvest via backend header-reflection endpoint (/debug/headers)

`UC_116_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.process_name IN ("curl","wget","python","python3") AND (Processes.process="*/debug/headers*" OR Processes.process="*x-tsdproxy-auth-token*")) by Processes.dest Processes.user Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("curl","wget","python","python3","curl.exe","wget.exe")
| where ProcessCommandLine has_any ("/debug/headers","x-tsdproxy-auth-token")
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
