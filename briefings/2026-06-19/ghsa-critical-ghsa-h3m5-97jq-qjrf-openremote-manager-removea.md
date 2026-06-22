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

### OpenRemote cross-realm alarm DELETE: single client deleting alarms in >1 realm (IDOR)

`UC_11_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as requests, min(_time) as firstTime, max(_time) as lastTime from datamodel=Web where Web.http_method=DELETE Web.url="*/alarm" by Web.src, Web.user, Web.url, Web.status
| `drop_dm_object_name("Web")`
| rex field=url "/api/(?<realm>[^/?]+)/alarm"
| where isnotnull(realm)
| stats sum(requests) as requests, values(realm) as realms, dc(realm) as realm_count, sum(eval(if(status>=200 AND status<300, requests, 0))) as successful_deletes, min(firstTime) as firstTime, max(lastTime) as lastTime by src, user
| where realm_count > 1
| convert ctime(firstTime) ctime(lastTime)
| sort - realm_count, - successful_deletes
```

### OpenRemote high-volume alarm DELETE to /api/*/alarm (mass destruction / scripted abuse)

`UC_11_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where Web.http_method=DELETE Web.url="*/alarm" (Web.status=200 OR Web.status=204) by Web.src, Web.user, Web.url, _time span=10m
| `drop_dm_object_name("Web")`
| rex field=url "/api/(?<realm>[^/?]+)/alarm"
| stats sum(count) as delete_requests, dc(realm) as realm_count, values(realm) as realms by src, user, _time
| where delete_requests >= 20
| sort - delete_requests
```

### OpenRemote alarm-endpoint authorization-failure cascade then success (IDOR boundary probing)

`UC_11_2` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where Web.http_method=DELETE Web.url="*/alarm" by Web.src, Web.user, Web.status, _time span=5m
| `drop_dm_object_name("Web")`
| stats sum(eval(if(status==401 OR status==403, count, 0))) as auth_failures, sum(eval(if(status>=200 AND status<300, count, 0))) as successes by src, user, _time
| where auth_failures >= 2 AND successes >= 1
| sort - auth_failures
```

### OpenRemote alarm-ID enumeration via 404-response probing across realms

`UC_11_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web where Web.http_method=DELETE Web.url="*/alarm" Web.status=404 by Web.src, Web.user, Web.url, _time span=10m
| `drop_dm_object_name("Web")`
| rex field=url "/api/(?<realm>[^/?]+)/alarm"
| stats sum(count) as probe_404s, dc(realm) as realm_count, values(realm) as realms by src, user, _time
| where probe_404s >= 15
| sort - probe_404s
```


## Why this matters

Severity classified as **CRIT** based on: 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
