# [MED] Security breach leaks the personal data of all 6.5 million Israeli voters

**Source:** Snyk
**Published:** 2020-02-12
**Article:** https://snyk.io/blog/security-breach-leaks-the-personal-data-of-all-6-5-million-israeli-voters/

## Threat Profile

Snyk Blog Written by Ran Bar zik 
February 12, 2020
0 mins read On the 10th of February, 2020 a security issue exposed the personal data of all 6,453,254 Israeli voters. The leak exposed personally identifiable information (PII) including full names, ID numbers, gender, addresses, and voting information.
Ran Bar Zik, an information security journalist and software engineer at Verizon Media group mentioned that this is the most severe and unprecedented security issue he had uncovered to date.
In …

## Indicators of Compromise (high-fidelity only)

- _No high-fidelity IOCs in the RSS summary._ If the source publishes a technical write-up with defanged IOCs in the body, those would be picked up automatically on the next pipeline run.

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1552** — Unsecured Credentials

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Access to exposed Elector '/get-admin-users' credential-leaking API endpoint

`UC_3388_0` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*/get-admin-users*" OR Web.uri_path="*/get-admin-users*") by Web.src, Web.dest, Web.site, Web.http_method, Web.status, Web.uri_path, Web.http_user_agent
| `drop_dm_object_name(Web)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```


## Why this matters

Severity classified as **MED** based on: 1 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
