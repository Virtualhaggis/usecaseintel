# [CRIT] Understanding filesystem takeover vulnerabilities in npm JavaScript package manager

**Source:** Snyk
**Published:** 2020-01-07
**Article:** https://snyk.io/blog/understanding-filesystem-takeover-vulnerabilities-in-npm-javascript-package-manager/

## Threat Profile

Snyk Blog In this article
Written by Liran Tal 
January 7, 2020
0 mins read On the 11th of December, 2019 a security vulnerability which extends to all major JavaScript package managers (npm, yarn and pnpm) was publicly disclosed. This vulnerability, discovered by security researcher Daniel Ruf , allows malicious actors to apply varied tactics of arbitrary file overwrites.
In this article:
How do Node.js command line packages work? 
How does this security vulnerability affect the npm package man…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2019-16776`
- **CVE:** `CVE-2019-16777`
- **CVE:** `CVE-2019-10773`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1195.002** — Compromise Software Supply Chain
- **T1574** — Hijack Execution Flow
- **T1546** — Event Triggered Execution

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable npm/yarn/pnpm version exposed to bin-key file overwrite (CVE-2019-16776/16777/10773)

`UC_3145_2` · phase: **delivery** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve IN ("CVE-2019-16776","CVE-2019-16777","CVE-2019-10773")) by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.signature Vulnerabilities.severity | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId in ("CVE-2019-16776","CVE-2019-16777","CVE-2019-10773")
| project DeviceName, DeviceId, OSPlatform, OSVersion, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### npm/yarn/pnpm planting or overwriting a binary in a system bin directory

`UC_3145_3` · phase: **install** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (Filesystem.action IN ("created","modified","write")) AND (Filesystem.file_path IN ("/usr/bin/*","/bin/*","/sbin/*","/usr/sbin/*","/usr/local/bin/*")) AND (Filesystem.file_name IN ("date","curl","wget","ssh","scp","sudo","bash","sh","git","python","python3","node","ls","cp","mv")) by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name | `drop_dm_object_name(Filesystem)` | convert ctime(firstTime) ctime(lastTime)
```

**Defender KQL:**
```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("node","npm","yarn","pnpm","node.exe","pnpm.cjs","npm-cli.js")
| where InitiatingProcessAccountName !endswith "$"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where (FolderPath in~ ("/usr/bin","/bin","/sbin","/usr/sbin"))
     or (FolderPath =~ "/usr/local/bin" and FileName in~ ("date","curl","wget","ssh","scp","sudo","bash","sh","git","python","python3","node","ls","cp","mv"))
| where not(InitiatingProcessCommandLine has_any ("nvm","corepack"))
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, ActionType, FileName, FolderPath, SHA256
| order by Timestamp desc
```

### Article-specific behavioural hunt — Understanding filesystem takeover vulnerabilities in npm JavaScript package mana

`UC_3145_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Understanding filesystem takeover vulnerabilities in npm JavaScript package mana ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("node.js","index.js"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_path="*/usr/bin/env*" OR Filesystem.file_path="*/usr/bin/date*" OR Filesystem.file_name IN ("node.js","index.js"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Understanding filesystem takeover vulnerabilities in npm JavaScript package mana
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("node.js", "index.js"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FolderPath has_any ("/usr/bin/env", "/usr/bin/date") or FileName in~ ("node.js", "index.js"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2019-16776`, `CVE-2019-16777`, `CVE-2019-10773`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 5 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
