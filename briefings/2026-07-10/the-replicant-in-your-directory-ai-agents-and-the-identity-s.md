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


These replicants already have accounts, permissions, and access to sensitive data. They are AI agents, service accounts,…

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
- **T1213** — Data from Information Repositories
- **T1078.004** — Valid Accounts: Cloud Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### UNC6395 Salesloft Drift bulk Salesforce export via impersonation User-Agents

`UC_2_2` · phase: **actions** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.http_user_agent="*Salesforce-Multi-Org-Fetcher*" OR Web.http_user_agent="*Salesforce-CLI/1.0*" OR Web.http_user_agent="*python-requests/2.32.4*" OR Web.http_user_agent="*aiohttp/3.12.15*") by Web.src Web.user Web.http_user_agent Web.dest Web.url | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let unc6395UA = dynamic(["Salesforce-Multi-Org-Fetcher","Salesforce-CLI/1.0","python-requests/2.32.4","aiohttp/3.12.15"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where Application == "Salesforce"
| where UserAgent has_any (unc6395UA)
| project Timestamp, Application, ActionType, AccountDisplayName, AccountObjectId, IPAddress, CountryCode, ISP, UserAgent, ObjectName, ObjectType, IsAdminOperation
| order by Timestamp desc
```

### UNC6395 source infrastructure (Tor + DigitalOcean/AWS) hitting cloud audit logs

`UC_2_3` · phase: **actions** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count values(Authentication.action) as action values(Authentication.signature) as signature min(_time) as firstTime max(_time) as lastTime from datamodel=Authentication where (Authentication.src IN ("208.68.36.90","44.215.108.109","154.41.95.2","176.65.149.100","179.43.159.198","185.130.47.58","185.207.107.130","194.15.36.117","195.47.238.178","195.47.238.83")) by Authentication.src Authentication.user Authentication.dest Authentication.app | `drop_dm_object_name(Authentication)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
let unc6395IP = dynamic(["208.68.36.90","44.215.108.109","154.41.95.2","176.65.149.100","179.43.159.198","185.130.47.58","185.207.107.130","194.15.36.117","195.47.238.178","195.47.238.83"]);
CloudAppEvents
| where Timestamp > ago(30d)
| where IPAddress in (unc6395IP) or ipv4_is_in_any_range(IPAddress, "185.220.101.0/24", "192.42.116.0/24")
| project Timestamp, Application, ActionType, AccountDisplayName, AccountObjectId, IPAddress, ISP, UserAgent, ObjectName, IsAdminOperation
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

Severity classified as **HIGH** based on: IOCs present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
