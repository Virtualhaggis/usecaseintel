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
- **T1087.004** — Account Discovery: Cloud Account
- **T1110.003** — Brute Force: Password Spraying
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1110.004** — Brute Force: Credential Stuffing
- **T1531** — Account Access Removal

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Entra sign-in with populated OAuth client ID but blank application name (spoofed client_id)

`UC_77_1` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as attempts, dc(Authentication.user) as distinct_users, values(Authentication.signature_id) as aadsts_codes, values(Authentication.action) as actions, min(_time) as firstTime, max(_time) as lastTime from datamodel=Authentication where nodename=Authentication (Authentication.app="" OR Authentication.app="unknown" OR Authentication.app="N/A") by Authentication.src, Authentication.dest | `drop_dm_object_name(Authentication)` | where attempts>1 | convert ctime(firstTime) ctime(lastTime) | sort - attempts
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where isnotempty(ApplicationId)
| where isempty(AppDisplayName) and isempty(Application)
| summarize AttemptCount = count(), DistinctUsers = dcount(AccountUpn), ErrorCodes = make_set(ErrorCode, 20), Clients = make_set(ClientAppUsed, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by ApplicationId, IPAddress
| where AttemptCount > 1
| order by AttemptCount desc
```

### Single source IP presenting many distinct spoofed OAuth client IDs (fragmentation to evade per-app detection)

`UC_77_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as attempts, dc(Authentication.user) as distinct_users, values(Authentication.signature_id) as aadsts_codes, min(_time) as firstTime, max(_time) as lastTime from datamodel=Authentication where nodename=Authentication (Authentication.app="" OR Authentication.app="unknown") Authentication.action=failure by Authentication.src, _time span=1h | `drop_dm_object_name(Authentication)` | where attempts>=20 AND distinct_users>=10 | convert ctime(firstTime) ctime(lastTime) | sort - attempts
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where isempty(AppDisplayName) and isnotempty(ApplicationId)
| summarize DistinctAppIds = dcount(ApplicationId), DistinctUsers = dcount(AccountUpn), Attempts = count(), AppSample = make_set(ApplicationId, 10) by IPAddress, bin(Timestamp, 1h)
| where DistinctAppIds >= 10   // a real app authenticates under ONE stable client ID; 10+ fictional IDs from one source in 1h = spoofing fan-out
| order by DistinctAppIds desc
```

### AADSTS700016 with blank app name — spoofed client ID confirms VALID Entra credentials

`UC_77_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count as hits, values(Authentication.src) as src, values(Authentication.app) as app, min(_time) as firstTime, max(_time) as lastTime from datamodel=Authentication where nodename=Authentication Authentication.signature_id=700016 by Authentication.user | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime) | sort - hits
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 700016   // app identifier not recognized, but username+password validated
| where isempty(AppDisplayName)
| summarize Hits = count(), Sources = make_set(IPAddress, 20), Apps = make_set(ApplicationId, 20), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountUpn
| order by LastSeen desc
```

### Account-lockout burst (AADSTS50053) driven by spoofed-client-ID enumeration

`UC_77_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` dc(Authentication.user) as locked_users, count as attempts, values(Authentication.src) as src from datamodel=Authentication where nodename=Authentication Authentication.signature_id=50053 by _time span=1h | `drop_dm_object_name(Authentication)` | where locked_users>=20 | sort - locked_users
```

**Defender KQL:**
```kql
AADSignInEventsBeta
| where Timestamp > ago(1d)
| where ErrorCode == 50053   // account locked from repeated failed attempts
| summarize LockedUsers = dcount(AccountUpn), Attempts = count(), BlankAppAttempts = countif(isempty(AppDisplayName)), DistinctApps = dcount(ApplicationId), Sources = make_set(IPAddress, 20) by bin(Timestamp, 1h)
| where LockedUsers >= 20   // mass lockout burst; campaign locked ~28% of targeted users
| where BlankAppAttempts > 0
| order by LockedUsers desc
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

Severity classified as **HIGH** based on: 5 use case(s) fired, 7 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
