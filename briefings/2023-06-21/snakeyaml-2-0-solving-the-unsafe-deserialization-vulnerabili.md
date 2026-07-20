# [CRIT] SnakeYaml 2.0: Solving the unsafe deserialization vulnerability

**Source:** Snyk
**Published:** 2023-06-21
**Article:** https://snyk.io/blog/snakeyaml-unsafe-deserialization-vulnerability/

## Threat Profile

Snyk Blog In this article
Written by Brian Vermeer 
June 21, 2023
0 mins read In the December of last year, we reported CVE-2022-1471 to you. This unsafe deserialization problem could easily lead to arbitrary code execution under the right circumstances. 
In the deep-dive blog post “ Unsafe deserialization vulnerability in SnakeYaml (CVE-2022-1471) ”, I explained the problems in this library and how it could be executed. The gist of the problem was that by default SnakeYaml parsed the incoming y…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2022-1471`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1059** — Command and Scripting Interpreter
- **T1105** — Ingress Tool Transfer

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### Vulnerable SnakeYAML <2.0 present (CVE-2022-1471 unsafe deserialization)

`UC_1663_1` · phase: **exploit** · confidence: **High** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Vulnerabilities where Vulnerabilities.cve="CVE-2022-1471" by Vulnerabilities.dest, Vulnerabilities.signature, Vulnerabilities.severity, Vulnerabilities.category
| `drop_dm_object_name(Vulnerabilities)`
| convert ctime(firstTime) ctime(lastTime)
| sort - severity
```

**Defender KQL:**
```kql
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId == "CVE-2022-1471"
| project Timestamp, DeviceName, DeviceId, SoftwareVendor, SoftwareName, SoftwareVersion, CveId, VulnerabilitySeverityLevel, RecommendedSecurityUpdate
| order by DeviceName asc
```

### JVM (java/javaw) spawning OS command interpreter — SnakeYAML gadget RCE outcome

`UC_1663_2` · phase: **exploit** · confidence: **Medium** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (Processes.parent_process_name="java.exe" OR Processes.parent_process_name="javaw.exe") AND (Processes.process_name IN ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe")) by Processes.dest, Processes.user, Processes.parent_process, Processes.process, Processes.process_name, Processes.parent_process_name
| `drop_dm_object_name(Processes)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe","curl.exe")
| where AccountName !endswith "$"
| project Timestamp, DeviceName, AccountName, ParentCmd = InitiatingProcessCommandLine, Child = FileName, ChildCmd = ProcessCommandLine, SHA256
| order by Timestamp desc
```

### JVM outbound fetch of remote class/JAR to public host — URLClassLoader gadget

`UC_1663_3` · phase: **delivery** · confidence: **Low** · AI-generated for this article

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic.All_Traffic where (All_Traffic.app="java" OR All_Traffic.app="javaw") AND All_Traffic.dest_category!="internal" by All_Traffic.src, All_Traffic.dest, All_Traffic.dest_port, All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| convert ctime(firstTime) ctime(lastTime)
| sort - lastTime
```

**Defender KQL:**
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe","javaw.exe")
| where RemoteIPType == "Public"
| where RemoteUrl has ".jar" or RemoteUrl has ".class" or isempty(RemoteUrl)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2022-1471`


## Why this matters

Severity classified as **CRIT** based on: CVE present, 4 use case(s) fired, 3 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
