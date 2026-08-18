# [HIGH] The Agent Baseline: 35 Controls, But Where Should You Start?

**Source:** Snyk
**Published:** 2026-08-12
**Article:** https://snyk.io/blog/agent-baseline-35-controls-where-should-you-start/

## Threat Profile

Snyk Blog In this article
Written by Krysztof Huszcza 
Ezra Tanzer 
August 12, 2026
0 mins read Two weeks ago, we published the Agent Baseline alongside Docker and Keycard. In it, we describe six security outcomes, 35 controls, and an open reference architecture for running AI agents at the enterprise level. Last week, we stress-tested it: we took it to a panel at Black Hat and spent about one hour being asked hard questions about it. 
The most useful question came from someone who had actually …

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

Severity classified as **HIGH** based on: 1 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
