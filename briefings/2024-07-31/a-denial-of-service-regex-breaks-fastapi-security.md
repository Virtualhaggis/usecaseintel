# [CRIT] A denial of service Regex breaks FastAPI security

**Source:** Snyk
**Published:** 2024-07-31
**Article:** https://snyk.io/blog/dos-regex-breaks-fastapi-security/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
July 31, 2024
0 mins read Welcome, fellow developers! In this blog post, we are going to delve deep into the world of application security, specifically focusing on a vulnerability that can deteriorate FastAPI security: Denial of service (DoS) caused by insecure regular expressions (regex). We'll explore how a poorly constructed regex can lead to what is known as regular expression denial of service (ReDoS), a form of DoS attack, and how these vuln…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2024-24762`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1499.003** — Endpoint Denial of Service: Application Exhaustion Flood

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### CVE-2024-24762 python-multipart ReDoS payload via crafted Content-Type header

`UC_1190_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime values(Web.uri_path) as uri_path values(Web.http_content_type) as content_type from datamodel=Web.Web where Web.http_method="POST" AND (Web.http_content_type="*\\\\\\\\*" OR Web.http_content_type="*application/x-www-form-urlencoded;*!=*" OR Web.http_content_type="*multipart/form-data;*!=*") by Web.src Web.dest Web.http_content_type
| `drop_dm_object_name(Web)`
| eval ct_len=len(content_type)
| where ct_len > 200 OR like(content_type,"%\\\\\\\\\\\\%")
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

### Inventory exposure: hosts running FastAPI / python-multipart vulnerable to CVE-2024-24762

`UC_1190_3` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstSeen max(_time) as lastSeen values(Vulnerabilities.signature) as signature values(Vulnerabilities.severity) as severity from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve="CVE-2024-24762" by Vulnerabilities.dest Vulnerabilities.cve
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstSeen) ctime(lastSeen)
| sort - lastSeen
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId == "CVE-2024-24762"
   or (SoftwareName has_any ("python-multipart","python_multipart") and SoftwareVersion matches regex @"^0\.0\.[0-6]$")
   or (SoftwareName =~ "fastapi" and SoftwareVersion matches regex @"^0\.10[0-8]\.")
   or (SoftwareName =~ "fastapi" and SoftwareVersion == "0.109.0")
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, OSPlatform, PublicIP, IsInternetFacing, LoggedOnUsers) by DeviceId
  ) on DeviceId
| project Timestamp, DeviceName, DeviceId, SoftwareName, SoftwareVersion, CveId,
          VulnerabilitySeverityLevel, RecommendedSecurityUpdate, IsInternetFacing, PublicIP
| order by IsInternetFacing desc, Timestamp desc
```

### Article-specific behavioural hunt — A denial of service Regex breaks FastAPI security

`UC_1190_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — A denial of service Regex breaks FastAPI security ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("main.py","node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("main.py","node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — A denial of service Regex breaks FastAPI security
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("main.py", "node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("main.py", "node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2024-24762`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
