# [CRIT] [GHSA / CRITICAL] GHSA-5rph-q42j-36j9: Duplicate Advisory: Picklescan has pickle parsing logic flaw that leads to malicious pickle file bypass

**Source:** GitHub Security Advisories
**Published:** 2026-06-17
**Article:** https://github.com/advisories/GHSA-5rph-q42j-36j9

## Threat Profile

Duplicate Advisory: Picklescan has pickle parsing logic flaw that leads to malicious pickle file bypass

## Duplicate Advisory

This advisory has been withdrawn because it is a duplicate of GHSA-9gvj-pp9x-gcfr. This link is maintained to preserve external references.

## Original Description

picklescan before 0.0.27 contains a parsing logic error in the _list_globals function when handling STACK_GLOBAL opcodes, failing to track arguments in the correct range and allowing malicious pickle files …

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2025-71325`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1195.001** — Compromise Software Dependencies and Development Tools

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable picklescan (CVE-2025-71325) inventory via TVM

`UC_57_1` · phase: **weapon** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities.Vulnerabilities where (Vulnerabilities.cve="CVE-2025-71325" OR (Vulnerabilities.signature="picklescan" AND Vulnerabilities.signature!="picklescan 0.0.27*")) by Vulnerabilities.dest Vulnerabilities.signature Vulnerabilities.severity Vulnerabilities.cve Vulnerabilities.vendor_product
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstTime) ctime(lastTime)
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(7d)
| where CveId == "CVE-2025-71325"
   or (SoftwareName =~ "picklescan" and SoftwareVersion startswith "0.0." and SoftwareVersion !in~ ("0.0.27","0.0.28","0.0.29","0.0.30"))
| join kind=leftouter (DeviceTvmSoftwareVulnerabilitiesKB | where CveId == "CVE-2025-71325" | project CveId, CvssScore, IsExploitAvailable, VulnerabilityDescription) on CveId
| project Timestamp, DeviceName, DeviceId, OSPlatform, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate, CvssScore, IsExploitAvailable
| sort by VulnerabilitySeverityLevel asc, DeviceName asc
```

### Picklescan CLI invocation on endpoint (vulnerable-scanner exposure hunt)

`UC_57_2` · phase: **install** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdlines values(Processes.parent_process_name) as parents from datamodel=Endpoint.Processes where (Processes.process="*picklescan*" OR Processes.process_name="picklescan.exe") AND Processes.user!="*$" by Processes.dest Processes.user Processes.process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "picklescan"
   or FileName =~ "picklescan.exe"
   or (FileName in~ ("python.exe","python3.exe","pythonw.exe") and ProcessCommandLine has_any ("-m picklescan","picklescan.cli","picklescan.scanner"))
| where AccountName !endswith "$"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Invocations=count(), SampleCmd=any(ProcessCommandLine), SampleParent=any(InitiatingProcessFileName) by DeviceName, AccountName, FileName
| order by LastSeen desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2025-71325`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 3 use case(s) fired, 2 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
