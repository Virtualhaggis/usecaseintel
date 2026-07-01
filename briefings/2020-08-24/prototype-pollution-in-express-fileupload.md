# [HIGH] Prototype pollution in express-fileupload

**Source:** Snyk
**Published:** 2020-08-24
**Article:** https://snyk.io/blog/prototype-pollution-in-express-fileupload/

## Threat Profile

Snyk Blog In this article
Written by Alyssa Miller 
August 24, 2020
0 mins read Welcome to the Snyk Monthly Vulnerability Profile. In this series, Snyk looks back on the vulnerabilities discovered by or reported to our Security Research Team . We choose one noteworthy vulnerability from the past month and tell the story behind the discovery, research, and disclosure of the vulnerability. We highlight the researchers, developers, and users who are helping identify and remediate vulnerabilities ac…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-7699`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059.003** — Command and Scripting Interpreter: Windows Command Shell
- **T1059.004** — Command and Scripting Interpreter: Unix Shell

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Node.js (Express) process spawning a command shell — express-fileupload prototype-pollution RCE outcome

`UC_3016_1` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="node.exe" OR Processes.parent_process_name="node") AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","sh","bash","dash","sh.exe","wsl.exe")) by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process | `drop_dm_object_name(Processes)` | where NOT match(process, "node_modules|node-gyp|prebuild|npm-cli|yarn") | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","bash.exe","sh.exe","wsl.exe","sh","bash","dash")
| where AccountName !endswith "$"
| where ProcessCommandLine !has "node_modules" and not(ProcessCommandLine has_any ("node-gyp","prebuild","npm ","yarn "))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, FolderPath, SHA256
| order by Timestamp desc
```

### Prototype-pollution payload (__proto__ / constructor.prototype) in inbound web requests to Express app

`UC_3016_2` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Web.Web where (Web.url="*__proto__*" OR Web.url="*constructor.prototype*" OR Web.uri_query="*__proto__*" OR Web.uri_query="*constructor.prototype*") by Web.src Web.dest Web.http_method Web.url Web.uri_query Web.status Web.http_user_agent | `drop_dm_object_name(Web)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

### Exposure: hosts running express-fileupload vulnerable to CVE-2020-7699

`UC_3016_3` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve="CVE-2020-7699" OR Vulnerabilities.signature="CVE-2020-7699") by Vulnerabilities.dest Vulnerabilities.severity Vulnerabilities.cve Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | convert ctime(firstTime) ctime(lastTime) | sort - lastTime
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2020-7699"
| project DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-7699`


## Why this matters

Severity classified as **HIGH** based on: CVE present, 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
