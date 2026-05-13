# [HIGH] Defense at AI speed: Microsoft’s new multi-model agentic security system tops leading industry benchmark

**Source:** Microsoft Security Blog
**Published:** 2026-05-12
**Article:** https://www.microsoft.com/en-us/security/blog/2026/05/12/defense-at-ai-speed-microsofts-new-multi-model-agentic-security-system-tops-leading-industry-benchmark/

## Threat Profile

Today Microsoft announced a major step forward in AI-powered cyber defense: our new agentic security system helped researchers find 16 new vulnerabilities across the Windows networking and authentication stack—including four Critical remote code execution flaws in components such as the Windows kernel TCP/IP stack and the IKEv2 service. They used the new Microsoft Security m ulti-mo d el a gentic s canning h arness (codename MDASH) which was built by Microsoft’s Autonomous Code Security team. Un…

## Indicators of Compromise (high-fidelity only)

- **CVE:** `CVE-2026-33827`
- **CVE:** `CVE-2026-40413`
- **CVE:** `CVE-2026-40405`
- **CVE:** `CVE-2026-33824`
- **CVE:** `CVE-2026-40406`
- **CVE:** `CVE-2026-35422`
- **CVE:** `CVE-2026-32209`
- **CVE:** `CVE-2026-35424`
- **CVE:** `CVE-2026-35423`
- **CVE:** `CVE-2026-40414`
- **CVE:** `CVE-2026-40401`
- **CVE:** `CVE-2026-40415`
- **CVE:** `CVE-2026-33096`
- **CVE:** `CVE-2026-40399`
- **CVE:** `CVE-2026-41089`
- **CVE:** `CVE-2026-41096`

## MITRE ATT&CK Techniques

- **T1190** — Exploit Public-Facing Application
- **T1204.002** — User Execution: Malicious File
- **T1210** — Exploitation of Remote Services
- **T1068** — Exploitation for Privilege Escalation

## Kill chain phases observed

_(none detected from narrative keywords)_

## Recommended hunts

### [LLM] Windows hosts exposed to MDASH-discovered May 2026 Patch Tuesday networking-stack CVEs

`UC_26_2` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
| tstats summariesonly=true count from datamodel=Vulnerabilities.Vulnerabilities where Vulnerabilities.cve IN ("CVE-2026-33827","CVE-2026-40413","CVE-2026-40405","CVE-2026-33824","CVE-2026-40406","CVE-2026-35422","CVE-2026-32209","CVE-2026-35424","CVE-2026-35423","CVE-2026-40414","CVE-2026-40401","CVE-2026-40415","CVE-2026-33096","CVE-2026-40399","CVE-2026-41089","CVE-2026-41096") by Vulnerabilities.dest Vulnerabilities.cve Vulnerabilities.severity Vulnerabilities.signature | `drop_dm_object_name(Vulnerabilities)` | stats values(cve) as exposed_cves dc(cve) as cve_count values(severity) as severities by dest | eval mdash_critical_rce=if(match(mvjoin(exposed_cves,","),"CVE-2026-33827|CVE-2026-33824|CVE-2026-41089|CVE-2026-41096"),"yes","no") | sort - mdash_critical_rce cve_count
```

**Defender KQL:**
```kql
let mdash_cves = dynamic(["CVE-2026-33827","CVE-2026-40413","CVE-2026-40405","CVE-2026-33824","CVE-2026-40406","CVE-2026-35422","CVE-2026-32209","CVE-2026-35424","CVE-2026-35423","CVE-2026-40414","CVE-2026-40401","CVE-2026-40415","CVE-2026-33096","CVE-2026-40399","CVE-2026-41089","CVE-2026-41096"]);
let mdash_critical_rce = dynamic(["CVE-2026-33827","CVE-2026-33824","CVE-2026-41089","CVE-2026-41096"]);
let device_ctx = DeviceInfo
    | where Timestamp > ago(1d)
    | summarize arg_max(Timestamp, OSPlatform, OSVersion, OSBuild, IsInternetFacing, MachineGroup, PublicIP) by DeviceId, DeviceName;
DeviceTvmSoftwareVulnerabilities
| where Timestamp > ago(1d)
| where CveId in (mdash_cves)
| where SoftwareName has_any ("windows", "tcpip", "netlogon", "ikeext", "dnsapi", "http.sys", "telnet")
| join kind=leftouter device_ctx on DeviceId
| summarize ExposedCves = make_set(CveId),
            CveCount = dcount(CveId),
            HasCriticalRCE = countif(CveId in (mdash_critical_rce)) > 0,
            RecommendedKB = make_set(RecommendedSecurityUpdate),
            MaxSeverity = max(VulnerabilitySeverityLevel),
            arg_max(Timestamp, OSVersion, OSBuild, IsInternetFacing, MachineGroup, PublicIP)
            by DeviceId, DeviceName
| extend Priority = case(HasCriticalRCE and IsInternetFacing == true, "P1-InternetFacing+CriticalRCE",
                          HasCriticalRCE, "P2-CriticalRCE",
                          IsInternetFacing == true, "P3-InternetFacing",
                          "P4-Standard")
| order by Priority asc, CveCount desc
```

### Article-specific behavioural hunt — Defense at AI speed: Microsoft’s new multi-model agentic security system tops le

`UC_26_1` · phase: **exploit** · confidence: **High**

**Splunk SPL (CIM):**
```spl
``` Article-specific bespoke detection — Defense at AI speed: Microsoft’s new multi-model agentic security system tops le ```
| tstats `summariesonly` count earliest(_time) AS firstTime latest(_time) AS lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name IN ("clfs.sys","tcpip.sys","ikeext.dll","telnet.exe","http.sys","netlogon.dll","dnsapi.dll"))
    by Processes.dest, Processes.user, Processes.process_name,
       Processes.process, Processes.parent_process_name, Processes.process_path
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| append [
| tstats `summariesonly` count
    from datamodel=Endpoint.Filesystem
    where Filesystem.action IN ("created","modified")
      AND (Filesystem.file_name IN ("clfs.sys","tcpip.sys","ikeext.dll","telnet.exe","http.sys","netlogon.dll","dnsapi.dll"))
    by Filesystem.dest, Filesystem.user, Filesystem.process_name,
       Filesystem.file_path, Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
]
```

**Defender KQL:**
```kql
// Article-specific bespoke detection — Defense at AI speed: Microsoft’s new multi-model agentic security system tops le
// Hunts the actual binaries / paths / commandline fragments named
// in the article instead of a generic technique-class template.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (FileName in~ ("clfs.sys", "tcpip.sys", "ikeext.dll", "telnet.exe", "http.sys", "netlogon.dll", "dnsapi.dll"))
| project Timestamp, DeviceName, AccountName, FileName,
          FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc

// File-creation events for the named binaries / paths
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileCreated","FileModified")
| where (FileName in~ ("clfs.sys", "tcpip.sys", "ikeext.dll", "telnet.exe", "http.sys", "netlogon.dll", "dnsapi.dll"))
| project Timestamp, DeviceName, AccountName, FolderPath,
          FileName, ActionType, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```

### IOC-driven hunts (use shared templates)

These are standard IOC-substitution hunts — the canonical SPL and KQL live once in [`_TEMPLATES.md`](../_TEMPLATES.md), so we don't repeat the same boilerplate on every CVE / hash / network-IOC briefing.

- **Asset exposure — vulnerability matches article CVE(s)** ([template](../_TEMPLATES.md#asset-exposure)) — phase: **recon**, confidence: **High**
  - CVE(s): `CVE-2026-33827`, `CVE-2026-40413`, `CVE-2026-40405`, `CVE-2026-33824`, `CVE-2026-40406`, `CVE-2026-35422`, `CVE-2026-32209`, `CVE-2026-35424` _(+8 more)_


## Why this matters

Severity classified as **HIGH** based on: CVE present, 3 use case(s) fired, 4 technique(s) inferred. Read the full article for actor attribution, tooling details, and any defanged IOCs in the body that aren't visible in the RSS summary.
