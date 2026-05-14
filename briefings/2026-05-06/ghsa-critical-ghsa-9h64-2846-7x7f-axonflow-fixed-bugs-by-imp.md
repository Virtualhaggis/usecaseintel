# [CRIT] [GHSA / CRITICAL] GHSA-9h64-2846-7x7f: Axonflow fixed bugs by implementing multi-tenant isolation and access-control hardening

**Source:** GitHub Security Advisories
**Published:** 2026-05-06
**Article:** https://github.com/advisories/GHSA-9h64-2846-7x7f

## Threat Profile

Axonflow fixed bugs by implementing multi-tenant isolation and access-control hardening

## Summary

Eight independently-filed bug fixes in the v7.1.3 → v7.5.0 release window collectively close a set of multi-tenant isolation, access-control, and policy-enforcement defects in the AxonFlow platform. They are filed as a single consolidated advisory because the recommended remediation is a single platform upgrade.

## Affected versions

`< 7.5.0`. Specific items affect different earlier minors; see…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1133** — External Remote Services
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] AxonFlow Onboard-Customer Endpoint Invocation (GHSA-9h64-2846-7x7f Item #3)

`UC_156_0` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Web.url) as urls values(Web.user_agent) as user_agents values(Web.status) as statuses from datamodel=Web where (Web.uri_path="*/onboard-customer*" OR Web.uri_path="*/api/v1/onboard*" OR Web.url="*onboard-customer*") by Web.src Web.dest Web.http_method | `drop_dm_object_name(Web)` | where http_method="POST" AND status<400 | sort - firstSeen
```

**Defender KQL:**
```kql
// Best-effort Defender hunt — DeviceNetworkEvents only sees URL on inspected HTTP traffic; HTTPS traffic surfaces only the SNI hostname. Pair with web-access-log telemetry for full coverage.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where RemoteUrl has_any ("onboard-customer","/api/v1/onboard")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### [LLM] SQL-Injection Pattern in Request Path/Query to AxonFlow Agent Hosts (Item #8 SQLI_ACTION Regression)

`UC_156_1` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Web.url) as urls values(Web.http_method) as methods values(Web.status) as statuses from datamodel=Web where (Web.dest="*axonflow.com*" OR Web.url="*axonflow.com*" OR Web.uri_path="*/api/v1/agent*" OR Web.uri_path="*/api/v1/map*") (Web.url="*union*select*" OR Web.url="*UNION*SELECT*" OR Web.url="*' OR *=*" OR Web.url="*information_schema*" OR Web.url="*--+*" OR Web.url="*/*!50000*" OR Web.url="*sleep(*" OR Web.url="*benchmark(*" OR Web.uri_query="*0x*select*") by Web.src Web.dest Web.http_method Web.url | `drop_dm_object_name(Web)` | sort 0 - count
```

**Defender KQL:**
```kql
// Outbound observation — any internal client probing try.getaxonflow.com with SQLi-shaped URLs while the SaaS endpoint ran a vulnerable SQLI_ACTION=warn default.
let sqli_tokens = dynamic(["union select","union%20select","information_schema","' or 1=1","%27%20or%201=1","%27%20OR%20%271%27=%271"," or 1=1","--","/*!50000","sleep(","benchmark(","0x3c","convert(int"]);
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType in ("ConnectionSuccess","HttpConnectionInspected")
| where RemoteUrl has "axonflow" or RemoteUrl has "getaxonflow.com"
| where RemoteUrl has_any (sqli_tokens)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, InitiatingProcessAccountName,
          RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
