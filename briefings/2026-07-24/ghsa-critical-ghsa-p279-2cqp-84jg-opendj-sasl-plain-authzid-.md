# [CRIT] [GHSA / CRITICAL] GHSA-p279-2cqp-84jg: OpenDJ SASL PLAIN authzid bypassing the proxy ACI scope check

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-p279-2cqp-84jg

## Threat Profile

OpenDJ SASL PLAIN authzid bypassing the proxy ACI scope check

### Summary
When a SASL PLAIN bind supplies an authorization identity (authzid) that resolves to a **different** user, PlainSASLMechanismHandler verified only the PROXIED_AUTH privilege and never evaluated the "proxy" access-control right (the mayProxy ACI scope check). As a result, any account holding the proxied-auth privilege could assume **any resolvable non-root identity** without being granted a proxy ACI for that target.

This…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1078** — Valid Accounts
- **T1134** — Access Token Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### OpenDJ SASL PLAIN bind invoking proxied authorization (authzid) — impersonation

`UC_78_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where Authentication.app="opendj" by Authentication.src_user, Authentication.user, Authentication.src, Authentication.dest 
| `drop_dm_object_name(Authentication)` 
| where isnotnull(src_user) AND isnotnull(user) AND lower(src_user)!=lower(user) 
| where NOT like(lower(user), "%cn=directory manager%") 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```

### OpenDJ proxied-auth fan-out — one source assuming many distinct authz identities

`UC_78_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Authentication where Authentication.app="opendj" by Authentication.src_user, Authentication.user, _time span=10m 
| `drop_dm_object_name(Authentication)` 
| where lower(src_user)!=lower(user) AND NOT like(lower(user), "%cn=directory manager%") 
| stats dc(user) as distinct_authzids values(user) as assumed_identities min(_time) as firstTime max(_time) as lastTime by src_user 
| where distinct_authzids >= 5 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
