# [HIGH] OAuth Client ID Spoofing Lets Attackers Validate Stolen Microsoft Entra Credentials

**Source:** The Hacker News
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/oauth-client-id-spoofing-lets-attackers.html

## Threat Profile

OAuth Client ID Spoofing Lets Attackers Validate Stolen Microsoft Entra Credentials 
 Ravie Lakshmanan  Jul 14, 2026 Cloud Security / Identity Security 
At least two distinct threat actors are weaponizing a novel evasion technique called OAuth client ID spoofing in cloud campaigns, while slipping past telemetry.
The activity allows users to enumerate user accounts and validate stolen credentials in Microsoft Entra ID environments, without ever generating a successful sign-in event that would o…

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
