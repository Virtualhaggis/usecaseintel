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
- **T1090** — Proxy
- **T1059** — Command and Scripting Interpreter
- **T1203** — Exploitation for Client Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### SonicWall SMA1000 unauthenticated SSRF via /wsproxy endpoint (CVE-2026-15409)

`UC_10_1` · phase: **delivery** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as http_method values(Web.http_user_agent) as user_agent from datamodel=Web where Web.url="*/wsproxy*" (Web.dest_port=443 OR Web.dest_port=8443 OR Web.url="*/wsproxy*") by Web.src, Web.dest, Web.url, Web.status | `drop_dm_object_name(Web)` | where NOT cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("192.168.0.0/16",src) AND NOT cidrmatch("172.16.0.0/12",src) | convert ctime(firstTime) ctime(lastTime) | sort - count
```

### SonicWall SMA1000 command injection via AMC sysCtrl.execRemoveHotfix RPC (CVE-2026-15410)

`UC_10_2` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Web.http_method) as http_method from datamodel=Web where (Web.url="*execRemoveHotfix*" OR Web.url="*sysCtrl.execRemoveHotfix*") by Web.src, Web.dest, Web.url, Web.status | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - count
```

### Exposure inventory: infrastructure assets carrying the InfraTrust KEV priority CVEs

`UC_10_3` · phase: **recon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Vulnerabilities.signature) as cve values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities where Vulnerabilities.signature IN ("CVE-2026-15409","CVE-2026-15410","CVE-2026-39808","CVE-2026-25089","CVE-2026-21385") by Vulnerabilities.dest, Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort - count
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in ("CVE-2026-15409","CVE-2026-15410","CVE-2026-39808","CVE-2026-25089","CVE-2026-21385")
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | project CveId, CvssScore, IsExploitAvailable) on CveId
| project DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, IsExploitAvailable, CvssScore, RecommendedSecurityUpdate
| sort by CvssScore desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-15409`, `CVE-2026-15410`, `CVE-2026-39808`, `CVE-2026-25089`, `CVE-2026-21385`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
