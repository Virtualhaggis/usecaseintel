# [HIGH] Hackers Breached Klue Integration to Steal Salesforce CRM Data via OAuth Tokens

**Source:** Cyber Security News
**Published:** 2026-06-18
**Article:** https://cybersecuritynews.com/klue-integration-breached-salesforce/

## Threat Profile

Threat actors exploited a trusted third-party SaaS integration to silently harvest enterprise CRM data, marking the latest chapter in an escalating wave of OAuth-abuse attacks targeting Salesforce ecosystems. Researchers at ReliaQuest observed attackers leveraging a compromised Klue Battlecards integration, a competitive-intelligence platform that synchronizes battlecard and win/loss data with Salesforce, to exfiltrate large volumes of [&#8230;] The post Hackers Breached Klue Integration to Stea…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `138.226.246.94`
- **IPv4 (defanged):** `212.86.125.24`
- **IPv4 (defanged):** `213.111.148.90`
- **IPv4 (defanged):** `94.154.32.160`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1071** — Application Layer Protocol

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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `138.226.246.94`, `212.86.125.24`, `213.111.148.90`, `94.154.32.160`


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 2 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
