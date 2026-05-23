# [CRIT] [GHSA / CRITICAL] GHSA-q2f7-m237-v562: @hulumi/policies: GitHub OIDC trust policy bypass via AWS set-qualified condition operators

**Source:** GitHub Security Advisories
**Published:** 2026-05-21
**Article:** https://github.com/advisories/GHSA-q2f7-m237-v562

## Threat Profile

@hulumi/policies: GitHub OIDC trust policy bypass via AWS set-qualified condition operators

Impact: @hulumi/policies versions before 1.3.2 only checked exact AWS IAM StringLike/StringEquals condition operator keys in G_OIDC_1. Set-qualified operators such as ForAnyValue:StringLike could hide wildcard GitHub Actions OIDC sub conditions from the mandatory guardrail.

Patched in 1.3.2: the AWS trust-policy inspector now evaluates set-qualified string operators and rejects unsafe GitHub OIDC sub co…

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1098.003** — Account Manipulation: Additional Cloud Roles
- **T1199** — Trusted Relationship
- **T1078.004** — Valid Accounts: Cloud Accounts
- **T1550.001** — Use Alternate Authentication Material: Application Access Token

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] AWS IAM role trust policy created with set-qualified operator on GitHub OIDC sub claim

`UC_47_0` · phase: **install** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(All_Changes.command) as policyDocument values(All_Changes.user) as user values(All_Changes.src) as src_ip values(All_Changes.user_agent) as user_agent from datamodel=Change where All_Changes.object_category="role" All_Changes.action IN ("created","modified","updated") All_Changes.vendor_product="AWS CloudTrail" by All_Changes.object
| `drop_dm_object_name(All_Changes)`
| where match(policyDocument, "(?i)(ForAnyValue|ForAllValues):String(Like|Equals)") AND match(policyDocument, "(?i)token\.actions\.githubusercontent\.com:sub")
| eval has_wildcard_sub=if(match(policyDocument, "(?i)token\.actions\.githubusercontent\.com:sub[^,}]*\*"),"yes","no")
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, object, user, src_ip, user_agent, has_wildcard_sub, policyDocument
```

### [LLM] AssumeRoleWithWebIdentity from GitHub OIDC with unexpected repo/branch sub claim

`UC_47_1` · phase: **exploit** · confidence: **Medium**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Authentication.src) as src_ip values(Authentication.user_agent) as user_agent from datamodel=Authentication where Authentication.action="success" Authentication.signature="AssumeRoleWithWebIdentity" Authentication.vendor_product="AWS CloudTrail" by Authentication.dest, Authentication.user
| `drop_dm_object_name(Authentication)`
| rex field=user "repo:(?<gh_org>[^/]+)/(?<gh_repo>[^:]+):(?<gh_ref>.+)"
| where isnotnull(gh_org)
| lookup approved_github_oidc_roles role_arn AS dest OUTPUT allowed_orgs, allowed_repos
| where isnull(allowed_orgs) OR NOT match(gh_org, allowed_orgs) OR (isnotnull(allowed_repos) AND NOT match(gh_repo, allowed_repos))
| convert ctime(firstTime) ctime(lastTime)
| table firstTime, lastTime, dest, gh_org, gh_repo, gh_ref, src_ip, user_agent, count
```


## Why this matters

Severity classified as **CRIT** based on: 2 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
