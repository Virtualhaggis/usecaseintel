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

- **T1550.001** — Use Alternate Authentication Material: Application Access Tokens
- **T1021.004** — Remote Services: SSH
- **T1068** — Exploitation for Privilege Escalation
- **T1528** — Steal Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Proxied backend process connecting to TSDProxy management port 127.0.0.1:8080

`UC_116_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="127.0.0.1" All_Traffic.dest_port=8080 NOT All_Traffic.process_name="*tsdproxy*" by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.process_name All_Traffic.process | `drop_dm_object_name(All_Traffic)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 8080
| where RemoteIP in ("127.0.0.1", "::1")
| where not(InitiatingProcessFileName has "tsdproxy")
| where isnotempty(InitiatingProcessFileName)
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, RemoteIP, RemotePort, LocalPort
| order by Timestamp desc
```

### TSDProxy management API /api/v1 access with spoofed x-tsdproxy-id identity header

`UC_116_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.url="*/api/v1/proxies*" OR Web.url="*/api/v1/*" Web.dest_port=8080 by Web.src Web.dest Web.dest_port Web.url Web.http_user_agent Web.status | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```

### TSDProxy leaking x-tsdproxy-auth-token into upstream backend requests (vulnerable-config exposure)

`UC_116_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_request_headers="*x-tsdproxy-auth-token*" by Web.dest Web.src Web.url | `drop_dm_object_name(Web)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | sort - lastTime
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
