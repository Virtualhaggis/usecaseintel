# [CRIT] Arbitrary code execution in Grunt

**Source:** Snyk
**Published:** 2020-09-21
**Article:** https://snyk.io/blog/arbitrary-code-execution-in-js-grunt/

## Threat Profile

Snyk Blog In this article
Written by Alyssa Miller 
September 21, 2020
0 mins read Welcome to the Snyk Monthly Vulnerability Profile. In this series, Snyk looks back on the vulnerabilities discovered by or reported to our Security Research Team . We choose one noteworthy vulnerability from the past month and tell the story behind the discovery, research, and disclosure of the vulnerability. We highlight the researchers, developers, and users who are helping identify and remediate vulnerabilities…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2020-7729`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.001** — Compromise Software Supply Chain: Compromise Software Dependencies and Development Tools
- **T1203** — Exploitation for Client Execution
- **T1059.007** — Command and Scripting Interpreter: JavaScript

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable Grunt < 1.3.0 exposed to YAML deserialization ACE (CVE-2020-7729)

`UC_3270_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where CveId == "CVE-2020-7729"
| project DeviceName, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, RecommendedSecurityUpdateId
| order by DeviceName asc
```

### Grunt task-runner (node.exe) spawning a command shell — possible js-yaml load() ACE

`UC_3270_2` · phase: **exploit** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="node.exe" Processes.parent_process="*grunt*" (Processes.process_name="cmd.exe" OR Processes.process_name="powershell.exe" OR Processes.process_name="pwsh.exe" OR Processes.process_name="sh.exe" OR Processes.process_name="bash.exe" OR Processes.process_name="wscript.exe" OR Processes.process_name="cscript.exe") by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "node.exe"
| where InitiatingProcessCommandLine has "grunt"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","sh.exe","bash.exe","wscript.exe","cscript.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, SHA256
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2020-7729`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
