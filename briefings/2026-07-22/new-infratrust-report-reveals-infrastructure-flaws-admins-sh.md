# [CRIT] New InfraTrust report reveals infrastructure flaws admins should patch first

**Source:** BleepingComputer
**Published:** 2026-07-22
**Article:** https://www.bleepingcomputer.com/news/security/new-infratrust-report-reveals-infrastructure-flaws-admins-should-patch-first/

## Threat Profile

New InfraTrust report reveals infrastructure flaws admins should patch first 
By Lawrence Abrams 
July 22, 2026
10:15 AM
0 
Eclypsium has launched InfraTrust, a new infrastructure cybersecurity knowledge base and monthly InfraTrust Pulse report designed to help organizations prioritize vulnerabilities affecting infrastructure, firmware, networking, and edge devices.
The monthly report aggregates security advisories from major infrastructure vendors and highlights the vulnerabilities administrato…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-15409`
- **CVE:** `CVE-2026-15410`
- **CVE:** `CVE-2026-39808`
- **CVE:** `CVE-2026-25089`
- **CVE:** `CVE-2026-21385`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Exposure hunt: internet-infrastructure devices carrying actively-exploited/KEV CVEs from July 2026 InfraTrust Pulse

`UC_18_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-15409","CVE-2026-15410","CVE-2026-39808","CVE-2026-25089","CVE-2026-21385") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2026-15409","CVE-2026-15410","CVE-2026-39808","CVE-2026-25089","CVE-2026-21385")
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, IsExploitAvailable, CvssScore, PublishedDate) on CveId
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsExploitAvailable, CvssScore
| order by CvssScore desc
```

### SonicWall SMA1000 pre-auth SSRF + management-console command injection exploitation (CVE-2026-15409/15410)

`UC_18_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.http_user_agent) as user_agent values(Web.url) as urls from datamodel=Web.Web where Web.http_method IN ("POST","PUT") AND (Web.url="*cgi-bin*" OR Web.url="*__api__*" OR Web.url="*workplace*" OR Web.url="*management*") AND (Web.url="*`*" OR Web.url="*$(*" OR Web.url="*%60*" OR Web.url="*%3B*" OR Web.url="*%7C*" OR Web.url="*;*" OR Web.url="*|*") by Web.src Web.dest Web.http_method | `drop_dm_object_name(Web)` | sort - count
```

### FortiSandbox unauthenticated OS command injection via crafted HTTP (CVE-2026-39808 / CVE-2026-25089)

`UC_18_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count values(Web.url) as urls values(Web.http_user_agent) as user_agent from datamodel=Web.Web where (Web.dest="*fortisandbox*" OR Web.dest="*fsa*" OR Web.http_method IN ("POST","PUT","GET")) AND (Web.url="*%60*" OR Web.url="*`*" OR Web.url="*$(*" OR Web.url="*%24%28*" OR Web.url="*%3B*" OR Web.url="*;*" OR Web.url="*%7C*" OR Web.url="*|*" OR Web.url="*%26%26*" OR Web.url="*&&*") by Web.src Web.dest Web.http_method | `drop_dm_object_name(Web)` | sort - count
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-15409`, `CVE-2026-15410`, `CVE-2026-39808`, `CVE-2026-25089`, `CVE-2026-21385`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
