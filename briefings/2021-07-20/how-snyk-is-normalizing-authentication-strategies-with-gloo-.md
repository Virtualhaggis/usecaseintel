# [MED] How Snyk is normalizing authentication strategies with Gloo Edge

**Source:** Snyk
**Published:** 2021-07-20
**Article:** https://snyk.io/blog/how-we-normalize-authentication-at-snyk-with-gloo-edge/

## Threat Profile

Snyk Blog In this article
Written by Joakim Bajoul Kakaei 
Jack Schofield 
David Harrigan 
Gareth Visagie 
James Bowes 
July 20, 2021
0 mins read Snyk supports multiple authentication (authN) strategies on its APIs. Historically, API keys have been the primary form of authN, but more recently we introduced support for authN using signed JWTs produced as a result of an OAuth integration. This is currently in use by both our AWS CodePipeline and Bitbucket integrations.
In the beginning, Snyk began…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

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

Severity classified as **MED** based on: 1 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
