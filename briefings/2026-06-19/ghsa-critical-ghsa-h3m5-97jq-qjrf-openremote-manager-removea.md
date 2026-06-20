# [CRIT] [GHSA / CRITICAL] GHSA-h3m5-97jq-qjrf: OpenRemote Manager: removeAlarms cross-realm IDOR (bulk delete)

**Source:** GitHub Security Advisories
**Published:** 2026-06-19
**Article:** https://github.com/advisories/GHSA-h3m5-97jq-qjrf

## Threat Profile

OpenRemote Manager: removeAlarms cross-realm IDOR (bulk delete)

### Summary
OpenRemote Manager is vulnerable to a cross-tenant Insecure Direct
Object Reference (IDOR) in the bulk alarm deletion endpoint. An
authenticated user in any realm can delete alarms belonging to other
realms (tenants) by supplying arbitrary alarm IDs. The vulnerability
exists because the bulk removeAlarms() method only verifies that the
caller's own realm is active and accessible, but never checks whether
the targeted al…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1485** — Data Destruction
- **T1190** — Exploit Public-Facing Application
- **T1580** — Cloud Infrastructure Discovery
- **T1087** — Account Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OpenRemote Manager bulk DELETE /api/{realm}/alarm — GHSA-h3m5-97jq-qjrf cross-tenant IDOR exploitation

`UC_1_0` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.http_method=DELETE Web.url="*/api/*/alarm*" by _time span=5m, Web.src, Web.user, Web.dest, Web.url, Web.status
| `drop_dm_object_name(Web)`
| stats sum(count) as deletes, dc(url) as endpoints, values(status) as response_codes by src, user, dest
| where deletes >= 3
| sort - deletes
```

### OpenRemote alarm-ID enumeration via DELETE /api/{realm}/alarm 404/200 oracle (GHSA-h3m5-97jq-qjrf)

`UC_1_1` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.http_method=DELETE Web.url="*/api/*/alarm*" by _time span=5m, Web.src, Web.user, Web.dest, Web.status
| `drop_dm_object_name(Web)`
| stats sum(count) as total,
        sum(eval(if(like(status,"4%"),count,0))) as fourxx,
        sum(eval(if(status="200",count,0))) as ok
      by src, user, dest
| eval err_ratio = round(fourxx / total, 2)
| where total >= 10 AND err_ratio >= 0.5
| sort - total
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
