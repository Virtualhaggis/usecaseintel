# [CRIT] [GHSA / CRITICAL] GHSA-6626-79jh-5ccr: Duplicate Advisory: phpMyFAQ enables unauthenticated 2FA brute-force attack via /admin/check acceptance of arbitrary user-id

**Source:** GitHub Security Advisories
**Published:** 2026-05-15
**Article:** https://github.com/advisories/GHSA-6626-79jh-5ccr

## Threat Profile

Duplicate Advisory: phpMyFAQ enables unauthenticated 2FA brute-force attack via /admin/check acceptance of arbitrary user-id

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-9pq7-mfwh-xx2j. This link is maintained to preserve external references.

### Original Description
phpMyFAQ before 4.1.2 contains an improper restriction of excessive authentication attempts vulnerability in the /admin/check endpoint, which accepts arbitrary user-id parameters withou…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1110.001** — Brute Force: Password Guessing
- **T1556.006** — Modify Authentication Process: Multi-Factor Authentication
- **T1190** — Exploit Public-Facing Application
- **T1078** — Valid Accounts

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### phpMyFAQ /admin/check unauthenticated TOTP brute-force (CVE GHSA-9pq7-mfwh-xx2j)

`UC_301_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.user) as users values(Web.http_user_agent) as ua values(Web.status) as statuses dc(Web.status) as distinctStatuses from datamodel=Web.Web where Web.http_method=POST Web.uri_path="/admin/check" by Web.src Web.dest _time span=5m | `drop_dm_object_name(Web)` | where count >= 30 | sort - count
```

### phpMyFAQ 2FA bypass success: /admin/check brute burst followed by authenticated /admin/ access

`UC_301_1` · phase: **install** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count as BruteAttempts min(_time) as BruteFirst max(_time) as BruteLast from datamodel=Web.Web where Web.http_method=POST Web.uri_path="/admin/check" by Web.src Web.dest | `drop_dm_object_name(Web)` | where BruteAttempts >= 20 | join type=inner src dest [| tstats summariesonly=true count as AdminHits min(_time) as AdminFirst from datamodel=Web.Web where Web.http_method=GET Web.uri_path IN ("/admin/","/admin/index.php","/admin/dashboard") Web.status IN (200,302) by Web.src Web.dest | `drop_dm_object_name(Web)`] | where AdminFirst >= BruteFirst AND AdminFirst <= (BruteLast + 600) | eval SecondsToAdmin=AdminFirst-BruteFirst | table BruteFirst, BruteLast, AdminFirst, SecondsToAdmin, src, dest, BruteAttempts, AdminHits
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
