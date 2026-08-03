# [CRIT] [GHSA / CRITICAL] GHSA-hp6v-6jw7-gv2f: Budibase: OIDC SSO account takeover: incoming identity linked by email without checking email_verified

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-hp6v-6jw7-gv2f

## Threat Profile

Budibase: OIDC SSO account takeover: incoming identity linked by email without checking email_verified

### Summary
Budibase's OIDC SSO login links an incoming SSO identity to an existing Budibase account **by email address alone**, without ever checking the `email_verified` claim of the OIDC ID token. Budibase first tries to match the IdP `sub`; when that misses (any fresh attacker IdP account) it silently falls back to matching by the `email` claim and **merges into the existing account by ema…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550** — Use Alternate Authentication Material
- **T1548** — Abuse Elevation Control Mechanism

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Budibase OIDC login sequence (configs → callback → self) from single source

`UC_124_0` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web.Web where (Web.url="*/api/global/auth/*/oidc/configs/*" OR Web.url="*/api/global/auth/oidc/callback*" OR Web.url="*/api/global/self*") by _time, Web.src, Web.dest, Web.uri_path span=1m | `drop_dm_object_name(Web)` | eval step=case(like(uri_path,"%/oidc/configs/%"),"1_init", like(uri_path,"%/oidc/callback%"),"2_callback", like(uri_path,"%/api/global/self%"),"3_self", 1==1,"other") | where step!="other" | stats dc(step) as steps values(step) as steps_seen min(_time) as firstTime max(_time) as lastTime by src, dest | where steps>=3 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```

### IdP self-registration or profile email-change asserting a privileged Budibase user's email

`UC_124_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Web.Web where (Web.uri_path="/api/global/auth/oidc/callback" OR Web.uri_path="/api/global/users" OR Web.uri_path="/api/global/roles" OR Web.uri_path="/api/global/configs") by _time, Web.src, Web.dest, Web.uri_path span=1m | `drop_dm_object_name(Web)` | eval isCallback=if(uri_path=="/api/global/auth/oidc/callback",1,0) | eval isAdmin=if(uri_path=="/api/global/users" OR uri_path=="/api/global/roles" OR uri_path=="/api/global/configs",1,0) | stats sum(isCallback) as callbacks sum(isAdmin) as adminCalls min(_time) as firstTime max(_time) as lastTime values(uri_path) as paths by src, dest | where callbacks>=1 AND adminCalls>=1 | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
