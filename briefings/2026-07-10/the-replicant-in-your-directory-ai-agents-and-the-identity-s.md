# [HIGH] The Replicant in Your Directory: AI Agents and the Identity Security Gap

**Source:** BleepingComputer
**Published:** 2026-07-10
**Article:** https://www.bleepingcomputer.com/news/security/the-replicant-in-your-directory-ai-agents-and-the-identity-security-gap/

## Threat Profile

The Replicant in Your Directory: AI Agents and the Identity Security Gap 
Sponsored by Netwrix 
July 10, 2026
10:00 AM
0 
By Grady Summers, CEO, Netwrix 
Security was built for people. AI agents are exposing the gap. 
Forty-four years after Blade Runner imagined replicants walking among us, security teams are managing their own version of a non-human workforce.
These replicants already have accounts, permissions, and access to sensitive data. They are AI agents, service accounts, OAuth applicati…

## Indicators of Compromise (high-fidelity only)

- **IPv4 (defanged):** `208.68.36.90`
- **IPv4 (defanged):** `44.215.108.109`
- **IPv4 (defanged):** `154.41.95.2`
- **IPv4 (defanged):** `176.65.149.100`
- **IPv4 (defanged):** `179.43.159.198`
- **IPv4 (defanged):** `185.130.47.58`
- **IPv4 (defanged):** `185.207.107.130`
- **IPv4 (defanged):** `185.220.101.133`
- **IPv4 (defanged):** `185.220.101.143`
- **IPv4 (defanged):** `185.220.101.164`
- **IPv4 (defanged):** `185.220.101.167`
- **IPv4 (defanged):** `185.220.101.169`
- **IPv4 (defanged):** `185.220.101.180`
- **IPv4 (defanged):** `185.220.101.185`
- **IPv4 (defanged):** `185.220.101.33`
- **IPv4 (defanged):** `192.42.116.179`
- **IPv4 (defanged):** `192.42.116.20`
- **IPv4 (defanged):** `194.15.36.117`
- **IPv4 (defanged):** `195.47.238.178`
- **IPv4 (defanged):** `195.47.238.83`

## MITRE ATT&CK Techniques

- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1071** — Application Layer Protocol
- **T1550.001** — Use Alternate Authentication Material: Application Access Token
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1213** — Data from Information Repositories
- **T1119** — Automated Collection
- **T1567** — Exfiltration Over Web Service
- **T1552.001** — Unsecured Credentials: Credentials In Files

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### UNC6395 Salesloft Drift OAuth abuse: Salesforce access from campaign Tor/API infra

`UC_34_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=saas (sourcetype=sfdc:* OR sourcetype=salesforce:*) (user_agent="Salesforce-Multi-Org-Fetcher/1.0" OR user_agent="Salesforce-CLI/1.0" OR user_agent="python-requests/2.32.4" OR user_agent="Python/3.11 aiohttp/3.12.15" OR src_ip IN ("208.68.36.90","44.215.108.109","154.41.95.2","176.65.149.100","179.43.159.198","185.130.47.58","185.207.107.130","185.220.101.133","185.220.101.143","185.220.101.164","185.220.101.167","185.220.101.169","185.220.101.180","185.220.101.185","185.220.101.33","192.42.116.179","192.42.116.20","194.15.36.117","195.47.238.178","195.47.238.83"))
| stats count as events min(_time) as firstTime max(_time) as lastTime values(action) as actions values(user) as users by src_ip user_agent
| sort - events
```

**Defender KQL:**
```kql
let UNC6395_IPs = dynamic(["208.68.36.90","44.215.108.109","154.41.95.2","176.65.149.100","179.43.159.198","185.130.47.58","185.207.107.130","185.220.101.133","185.220.101.143","185.220.101.164","185.220.101.167","185.220.101.169","185.220.101.180","185.220.101.185","185.220.101.33","192.42.116.179","192.42.116.20","194.15.36.117","195.47.238.178","195.47.238.83"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "Salesforce"
| where IPAddress in (UNC6395_IPs) or UserAgent has_any ("Salesforce-Multi-Org-Fetcher/1.0","Salesforce-CLI/1.0","python-requests/2.32.4","aiohttp/3.12.15")
| project Timestamp, Application, ActionType, AccountDisplayName, AccountObjectId, IPAddress, UserAgent, CountryCode, ISP, ObjectName, ObjectType, IsAdminOperation
| order by Timestamp desc
```

### UNC6395 bulk SOQL export fan-out from Salesforce (mass record harvesting)

`UC_34_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=saas (sourcetype=sfdc:* OR sourcetype=salesforce:*) (user_agent="Salesforce-Multi-Org-Fetcher/1.0" OR user_agent="Salesforce-CLI/1.0" OR user_agent="python-requests/2.32.4" OR user_agent="Python/3.11 aiohttp/3.12.15" OR src_ip IN ("208.68.36.90","44.215.108.109","154.41.95.2","176.65.149.100","179.43.159.198","185.130.47.58","185.207.107.130","185.220.101.133","185.220.101.143","185.220.101.164","185.220.101.167","185.220.101.169","185.220.101.180","185.220.101.185","185.220.101.33","192.42.116.179","192.42.116.20","194.15.36.117","195.47.238.178","195.47.238.83"))
| bin _time span=1h
| stats count as events dc(sobject) as objects_touched values(action) as actions values(query) as queries by _time user src_ip user_agent
| where events > 100
| sort - events
```

**Defender KQL:**
```kql
let UNC6395_IPs = dynamic(["208.68.36.90","44.215.108.109","154.41.95.2","176.65.149.100","179.43.159.198","185.130.47.58","185.207.107.130","185.220.101.133","185.220.101.143","185.220.101.164","185.220.101.167","185.220.101.169","185.220.101.180","185.220.101.185","185.220.101.33","192.42.116.179","192.42.116.20","194.15.36.117","195.47.238.178","195.47.238.83"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "Salesforce"
| where UserAgent has_any ("Salesforce-Multi-Org-Fetcher/1.0","Salesforce-CLI/1.0","python-requests/2.32.4","aiohttp/3.12.15") or IPAddress in (UNC6395_IPs)
| summarize EventCount = count(), ObjectsTouched = dcount(ObjectId), Actions = make_set(ActionType, 25), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by AccountDisplayName, IPAddress, UserAgent, bin(Timestamp, 1h)
| where EventCount > 100  // automated bulk SOQL/export fan-out; tune to org P99 API volume
| order by EventCount desc
```

### UNC6395 follow-on AWS API use from Drift-harvested AKIA keys via Tor egress

`UC_34_4` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
index=aws sourcetype=aws:cloudtrail src_ip IN ("208.68.36.90","44.215.108.109","154.41.95.2","176.65.149.100","179.43.159.198","185.130.47.58","185.207.107.130","185.220.101.133","185.220.101.143","185.220.101.164","185.220.101.167","185.220.101.169","185.220.101.180","185.220.101.185","185.220.101.33","192.42.116.179","192.42.116.20","194.15.36.117","195.47.238.178","195.47.238.83")
| stats count as events min(_time) as firstTime max(_time) as lastTime values(eventName) as api_calls values(userIdentity.arn) as arns values(userAgent) as user_agents by src_ip awsRegion
| sort - events
```

**Defender KQL:**
```kql
let UNC6395_IPs = dynamic(["208.68.36.90","44.215.108.109","154.41.95.2","176.65.149.100","179.43.159.198","185.130.47.58","185.207.107.130","185.220.101.133","185.220.101.143","185.220.101.164","185.220.101.167","185.220.101.169","185.220.101.180","185.220.101.185","185.220.101.33","192.42.116.179","192.42.116.20","194.15.36.117","195.47.238.178","195.47.238.83"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application has "Amazon Web Services"
| where IPAddress in (UNC6395_IPs)
| project Timestamp, ActionType, AccountDisplayName, AccountId, IPAddress, UserAgent, IsAdminOperation, ObjectName, ObjectType, CountryCode, ISP
| order by Timestamp desc
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

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Network connections to article IPs / domains** ([template](../_TEMPLATES.md#network-ioc)) — phase: **c2**, confidence: **High**
  - IP / domain IOC(s): `208.68.36.90`, `44.215.108.109`, `154.41.95.2`, `176.65.149.100`, `179.43.159.198`, `185.130.47.58`, `185.207.107.130`, `185.220.101.133` _(+12 more)_


## Why this matters

Severity classified as **HIGH** based on: IOCs present, 5 use case(s) fired, 9 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
