# [HIGH] Hackers Breached Klue Integration to Steal Salesforce CRM Data via OAuth Tokens

**Source:** Cyber Security News
**Published:** 2026-06-18
**Article:** https://cybersecuritynews.com/klue-integration-breached-salesforce/

## Threat Profile

Threat actors exploited a trusted third-party SaaS integration to silently harvest enterprise CRM data, marking the latest chapter in an escalating wave of OAuth-abuse attacks targeting Salesforce ecosystems. Researchers at ReliaQuest observed attackers leveraging a compromised Klue Battlecards integration, a competitive-intelligence platform that synchronizes battlecard and win/loss data with Salesforce, to exfiltrate large volumes of [&#8230;] The post Hackers Breached Klue Integration to Stea…

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
