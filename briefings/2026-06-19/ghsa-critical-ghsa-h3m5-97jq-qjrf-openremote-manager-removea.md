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

- **T1190** — Exploit Public-Facing Application
- **T1485** — Data Destruction
- **T1087** — Account Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OpenRemote Manager bulk alarm DELETE endpoint hit (GHSA-h3m5-97jq-qjrf)

`UC_3_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.http_method="DELETE" Web.url="*/api/*/alarm" Web.status IN (200,204) by _time, Web.src, Web.user, Web.dest, Web.url, Web.status span=1m | rename Web.* as * | rex field=url "/api/(?<realm>[^/]+)/alarm$" | where isnotnull(realm) | stats count by _time, src, user, dest, realm, status
```

### Bulk alarm DELETE volume anomaly — non-admin OpenRemote user

`UC_3_1` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.http_method="DELETE" Web.url="*/api/*/alarm" Web.status IN (200,204) by _time, Web.src, Web.user, Web.dest span=10m | rename Web.* as * | where count >= 20 | sort - count
```

### OpenRemote alarm DELETE 401/403 probe burst followed by 200/204 success

`UC_3_2` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.http_method="DELETE" Web.url="*/api/*/alarm" by _time, Web.src, Web.user, Web.status span=1m | rename Web.* as * | eval bucket=floor(_time/300)*300 | eval is_fail=if(status IN ("401","403"),count,0), is_ok=if(status IN ("200","204"),count,0) | stats sum(is_fail) as Failures, sum(is_ok) as Successes, earliest(_time) as FirstSeen, latest(_time) as LastSeen by bucket, src, user | where Failures >= 2 AND Successes >= 3
```

### OpenRemote alarm endpoint enumeration with realm-switching

`UC_3_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.http_method="DELETE" Web.url="*/api/*/alarm" by _time, Web.src, Web.user, Web.url span=1m | rename Web.* as * | rex field=url "/api/(?<realm>[^/]+)/alarm$" | where isnotnull(realm) | bin _time span=10m | stats dc(realm) as DistinctRealms, values(realm) as Realms, sum(count) as TotalDeletes by _time, src, user | where DistinctRealms >= 2 AND TotalDeletes >= 10
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
