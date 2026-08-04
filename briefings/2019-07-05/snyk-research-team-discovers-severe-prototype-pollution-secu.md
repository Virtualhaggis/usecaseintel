# [CRIT] Snyk research team discovers severe prototype pollution security vulnerabilities affecting all versions of lodash

**Source:** Snyk
**Published:** 2019-07-05
**Article:** https://snyk.io/blog/snyk-research-team-discovers-severe-prototype-pollution-security-vulnerabilities-affecting-all-versions-of-lodash/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
July 5, 2019
0 mins read On July 2nd, 2019, Snyk published a high severity prototype pollution security vulnerability (CVE-2019-10744) affecting all versions of lodash, as the result of an on-going analysis lead by the Snyk security research team.
UPDATE: lodash published version 4.17.12 on July 9th which includes Snyk fixes and remediates the vulnerability. We strongly recommend you update to the latest version of lodash. 
No official fix for this…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-10744`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable lodash (CVE-2019-10744 prototype pollution) present in software inventory

`UC_3518_2` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2019-10744" OR (Vulnerabilities.signature="*lodash*" AND Vulnerabilities.signature="*prototype pollution*") by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId =~ "CVE-2019-10744" or (SoftwareName has "lodash" and SoftwareVersion startswith "4.")
| project Timestamp, DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by Timestamp desc
```

### Prototype pollution payload (__proto__ / constructor.prototype) in inbound web requests

`UC_3518_3` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Web where (Web.uri_query="*__proto__*" OR Web.uri_query="*%5f%5fproto%5f%5f*" OR (Web.uri_query="*constructor*" AND Web.uri_query="*prototype*") OR Web.uri_path="*__proto__*") by Web.src Web.dest Web.http_method Web.uri_path Web.uri_query Web.http_user_agent Web.status | `drop_dm_object_name(Web)` | sort - lastTime
```

### Article-specific behavioural hunt — Snyk research team discovers severe prototype pollution security vulnerabilities

`UC_3518_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Snyk research team discovers severe prototype pollution security vulnerabilities ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("node.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Snyk research team discovers severe prototype pollution security vulnerabilities
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("node.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2019-10744`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
