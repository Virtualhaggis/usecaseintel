# [HIGH] AI Is Building Your Attack Surface. Are You Testing It?

**Source:** Snyk
**Published:** 2026-03-19
**Article:** https://snyk.io/blog/ai-is-building-your-attack-surface-are-you-testing-it/

## Threat Profile

Snyk Blog In this article
Written by Manoj Nair 
March 19, 2026
0 mins read The market is flooded with claims. One vendor tops a leaderboard. Another raises nine figures on a pitch deck. Meanwhile, your developers shipped three AI-generated services before lunch. Here's the conversation the industry isn't having, and the one we've been building toward for years. 
There's a version of this conversation happening inside every Security team right now.
Someone demos an AI coding assistant. The speed…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-12420`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1556** — Modify Authentication Process
- **T1136.003** — Create Account: Cloud Account
- **T1098.003** — Account Manipulation: Additional Cloud Roles

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### BodySnatcher (CVE-2025-12420) ServiceNow Virtual Agent bot/integration exploit

`UC_573_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where Web.url="*/api/sn_va_as_service/bot/integration*" by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.status Web.user
| `drop_dm_object_name(Web)`
| where user="unauthenticated" OR isnull(user) OR user="guest"
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### BodySnatcher post-exploit: backdoor admin account / role grant via ServiceNow AI agent

`UC_573_2` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Change where (Change.object="sys_user_has_role" OR (Change.object="sys_user" AND Change.action=created)) by Change.user Change.object Change.action Change.command Change.dest Change.object_id
| `drop_dm_object_name(Change)`
| search command="*2831a114c611228501d4ea6c309d626d*" OR object="sys_user"
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-12420`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
