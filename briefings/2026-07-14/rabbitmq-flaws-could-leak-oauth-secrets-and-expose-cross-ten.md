# [CRIT] RabbitMQ Flaws Could Leak OAuth Secrets and Expose Cross-Tenant Queue Metadata

**Source:** The Hacker News
**Published:** 2026-07-14
**Article:** https://thehackernews.com/2026/07/rabbitmq-flaws-could-leak-oauth-secrets.html

## Threat Profile

RabbitMQ Flaws Could Leak OAuth Secrets and Expose Cross-Tenant Queue Metadata 
 Ravie Lakshmanan  Jul 14, 2026 Vulnerability / Network Security 
Cybersecurity researchers have disclosed details of two access control-related flaws impacting the RabbitMQ message broker service that could allow attackers to leak OAuth client secrets, expose enterprise messaging infrastructure to takeover risks, and bypass tenant boundaries.
Miggo's security team, which discovered and reported the flaws, said one…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-57219`
- **CVE:** `CVE-2026-57221`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1528** — Steal Application Access Token
- **T1098.001** — Account Manipulation: Additional Cloud Credentials
- **T1552.001** — Unsecured Credentials: Credentials In Files
- **T1087** — Account Discovery
- **T1580** — Cloud Infrastructure Discovery

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Unauthenticated GET /api/auth on RabbitMQ management port leaking OAuth client secret (CVE-2026-57219)

`UC_64_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.http_method=GET Web.dest_port=15672 (Web.uri_path="/api/auth" OR Web.url="*/api/auth*") by Web.src, Web.dest, Web.dest_port, Web.uri_path, Web.status, Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Cross-tenant RabbitMQ queue/exchange enumeration via management API (CVE-2026-57221)

`UC_64_3` · phase: **recon** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Web where Web.http_method=GET Web.dest_port=15672 (Web.uri_path="/api/queues*" OR Web.uri_path="/api/exchanges*") by Web.src, Web.dest, Web.uri_path
| `drop_dm_object_name(Web)`
| stats dc(uri_path) as distinctPaths sum(count) as totalRequests values(uri_path) as sampledPaths by src, dest
| where distinctPaths > 20
| sort - distinctPaths
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

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-57219`, `CVE-2026-57221`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 6 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
