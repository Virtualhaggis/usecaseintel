# [CRIT] Cache poisoning in popular open source packages

**Source:** Snyk
**Published:** 2021-01-18
**Article:** https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/

## Threat Profile

Snyk Blog In this article
Written by Adam Goldschmidt 
January 18, 2021
0 mins read Following research done by James Kettle from PortSwigger on web cache poisoning, Snyk’s Security Team decided to deepen our knowledge in this field and to explore these vulnerabilities in the open source domain. We focused our research on the most popular web frameworks both in npm and PyPi, such as Flask ( Werkzeug ), Bottle , Tornado , and DerbyJS .
This blog post provides an introduction to web cache poisoning…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2021-23336`
- **CVE:** `CVE-2020-28473`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Semicolon GET parameter cloaking in web/proxy logs (cache poisoning, CVE-2021-23336 / CVE-2020-28473)

`UC_3233_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where Web.http_method=* by Web.src, Web.dest, Web.http_user_agent, Web.status, Web.url | `drop_dm_object_name(Web)` | where match(url, "(?i)\?[^#]*;[a-zA-Z0-9_.\-]{1,40}=") | eval marketing_cloak=if(match(url,"(?i)[?&;]utm_[a-z]+="),"yes","no") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### Assets exposed to cache-poisoning CVEs (Python parse_qsl CVE-2021-23336 / Bottle CVE-2020-28473)

`UC_3233_2` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2021-23336","CVE-2020-28473") by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.cve, Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in ("CVE-2021-23336", "CVE-2020-28473")
| project Timestamp, DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2021-23336`, `CVE-2020-28473`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 1 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
