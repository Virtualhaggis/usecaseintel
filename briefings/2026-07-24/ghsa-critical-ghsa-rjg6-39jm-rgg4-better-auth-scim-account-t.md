# [CRIT] [GHSA / CRITICAL] GHSA-rjg6-39jm-rgg4: @better-auth/scim: account takeover and stale access via SCIM provider-id collision

**Source:** GitHub Security Advisories
**Published:** 2026-07-24
**Article:** https://github.com/advisories/GHSA-rjg6-39jm-rgg4

## Threat Profile

@better-auth/scim: account takeover and stale access via SCIM provider-id collision

### Am I affected?

You are affected if your application registers the `@better-auth/scim` plugin and lets authenticated users generate SCIM tokens. The default `canGenerateToken` policy was affected, and custom policies were affected when they did not reject provider IDs already used by other account providers. The provider-ID collision issue additionally requires SSO, SAML, OIDC, generic OAuth, or social provi…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1531** — Account Access Removal
- **T1550.001** — Use Alternate Authentication Material: Application Access Tokens
- **T1098** — Account Manipulation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Better-Auth SCIM global user deletion via /scim/v2/Users from unsanctioned caller

`UC_83_1` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as delete_count min(_time) as firstTime max(_time) as lastTime values(Web.status) as statuses values(Web.http_user_agent) as user_agents from datamodel=Web where Web.http_method=DELETE Web.url="*/scim/v2/Users/*" (Web.status=200 OR Web.status=204) by Web.src Web.user Web.site Web.dest
| `drop_dm_object_name(Web)`
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| sort - lastTime
```

### Better-Auth SCIM profile/email rewrite fan-out across many /scim/v2/Users resources

`UC_83_2` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as write_count dc(Web.url) as distinct_user_resources values(Web.http_method) as methods min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_method=PUT OR Web.http_method=PATCH) Web.url="*/scim/v2/Users/*" Web.status>=200 Web.status<300 by Web.src Web.user Web.site
| `drop_dm_object_name(Web)`
| where distinct_user_resources > 5
| eval firstTime=strftime(firstTime,"%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime,"%Y-%m-%d %H:%M:%S")
| sort - write_count
```

### OAuth consent / suspicious app grant

`UC_OAUTH_ABUSE` · phase: **actions** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Authentication.Authentication
    where Authentication.action="success"
      AND Authentication.signature IN (
        "Consent to application",
        "Add app role assignment grant to user",
        "Add OAuth2PermissionGrant",
        "Add delegated permission grant")
    by Authentication.user, Authentication.app, Authentication.src, Authentication.signature
| `drop_dm_object_name(Authentication)`
```

**Defender KQL:**
```kql
CloudAppEvents
| where Timestamp > ago(7d)
| where ActionType in ("Consent to application.","Add OAuth2PermissionGrant.","Add delegated permission grant.")
| project Timestamp, AccountObjectId, AccountDisplayName, ActivityType,
          ActivityObjects, IPAddress, UserAgent
```


## Why this matters

Severity classified as **CRIT** based on: 3 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
