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

### TSDProxy x-tsdproxy-auth-token leaked to backend in upstream HTTP requests

`UC_229_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (sourcetype=*proxy* OR sourcetype=*access* OR sourcetype=*nginx* OR sourcetype=*tsdproxy* OR sourcetype=*syslog*) ("x-tsdproxy-auth-token" OR "X-Tsdproxy-Auth-Token")
| stats count min(_time) as firstTime max(_time) as lastTime values(uri_path) as paths values(dest) as backends values(src) as sources by host, sourcetype
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

### TSDProxy management-port replay: loopback connection to 127.0.0.1:8080 by non-proxy process

`UC_229_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_ip="127.0.0.1" All_Traffic.dest_port=8080 by All_Traffic.src, All_Traffic.dest_ip, All_Traffic.dest_port, All_Traffic.process_name, host
| `drop_dm_object_name(All_Traffic)`
| search NOT process_name IN ("tsdproxy","tsdproxyd")
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP in ("127.0.0.1", "::1") and RemotePort == 8080
| where isnotempty(InitiatingProcessFileName) and InitiatingProcessFileName !contains "tsdproxy"
| where InitiatingProcessAccountName !endswith "$"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine, InitiatingProcessAccountName, LocalIP, RemoteIP, RemotePort
| order by Timestamp desc
```

### TSDProxy management API abuse: /api/v1 request with forged x-tsdproxy-id and auth token

`UC_229_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=* (sourcetype=*proxy* OR sourcetype=*access* OR sourcetype=*nginx* OR sourcetype=*tsdproxy* OR sourcetype=*syslog*) "x-tsdproxy-id" ("/api/v1/" OR "/api/v2/")
| stats count min(_time) as firstTime max(_time) as lastTime values(uri_path) as paths values(src) as sources by host, sourcetype
| convert ctime(firstTime) ctime(lastTime)
| sort - count
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
